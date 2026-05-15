# General design of how the webhook support works

Beyla can operate it's own Kubernetes webhook for SDK injection, or use an external controller.
When using an external controller, Beyla does the job of existing local process discovery, so that
the controller can automatically restart deployments which are deemed as eligible for instrumentation.


## General local webhook operation (will be deprecated soon)

1. Requires that certmanager is installed on the cluster, so that Beyla can get TLS credentials from it.
2. Once the TLS credentials are acquired, Beyla launches the webhook, meaning it can intercept any
   new pod launches. These new pods are instrumented using the OpenTelemetry Injector with only 4
   supported languages at the moment: Java, .NET, Node.js and Python.
3. Apart from the new pods, we want to instrument all existing eligible deployments in the cluster.
   This means we'll need to restart certain deployments with a proper rollout in Kubernetes. For
   this purpose Beyla establishes an initial process state after it has registered the webhook.
   The local processes are then enriched with information about:
    - Their programming language
    - Their environment variables
    - Their container information

   This creates the so called initial process state. It's created when the k8s informers send the first pod information.
4. Beyla then registers with the k8 informers and starts receiving the new pod events, listing all
   existing pods. When the pod information comes we:
    - Discard any pods for nodes that don't belong to this current node where Beyla is running.
      This is important since Beyla typically is configured to see cluster wide information.
    - For each pod, consult the local process state. If matched we correlate the pod information with
      the process attributes, by the container ID, and then decide if this deployment should be 
      restarted. The restart happens by adding a label to the deployment, which in turn creates
      gracefull rollout of the deployment.
    - If we fail to find the process attributes we do a rebuild of the process state, while we
      haven't received all of the initial state from the k8s informers. Once all of the inital 
      k8s state is received we don't try to rebuild the local process state.
5. After the initial state is processed, new events from the k8s informers typically don't find 
   a thing, and we purely rely on the webhook to add instrumentation.

## Instrumentation modes

We currently support two instrumentation modes:

### Using host path (for old kubernetes versions, prior to 1.31)

In this mode, we register a host path volume on each Beyla deployment and then we run the
injector package as an init container on the Beyla deployment. This mode requires that we
set the volume path and the SDK version, so that Beyla can manage the volume appropriately.
The injector Docker image default command `copy-to-volume.sh` puts all the injector files,
versioned with the SDK version config field, in this volume. 

Beyla then adds this volume for each newly instrumented pod. The volume is read-only and the
same volume is attached to all pods.

### Using the image volume directly (Kubernetes versions 1.31+)

In the Kubernetes versions greater or equal to 1.31, a container image can directly be mounted
as read only volume by pods. In this mode, Beyla is just given the path to the injector image
and it simply mounts it as read-only volume to each instrumented pod. The injector image
is structured in a way that `copy-to-volume.sh` and direct mount produce the same exact
folder structure and we can use both injection modes interchangeably. 

## External webhook controller mode

This will be the default mode in which Beyla SDK injection will run. The controller will
replace the following Beyla functionalities:
  1. The webhook and registering with cert manager.
  2. The injection of the instrumentation. The only supported mode right now will be the
     Kubernetes 1.31+ mode with direct image mount.
  3. The pod bouncing logic, that is the pod labelling to force a restart.

What the controller cannot do is investigate the local processes on each node to determine
which deployments should be restarted if they are eligible for instrumentation. For this
we still need the local Beyla daemonset. This means that Beyla should somehow communicate 
to the controller which deployments should be considered for restart.

### Communicating the eligible deployments from Beyla to the Controller

The communication happens via config maps. These config maps also contain other information,
such as the local node exporter endpoint for those services and the SDK image that should be
injected. While these can be configured on the controller, especially if there's a global
collector load balanacer, having them communicated by Beyla allows for updating them dynamically
through fleet management or OpAMP.

The updating of eligible deployments works the following way:

1. We want to find all existing eligible deployments in the cluster that should be communicated
   to the controller.For this purpose Beyla establishes an initial process state after it has registered to listen for pods though the k8s informers.
   The local processes are then enriched with information about:
    - Their programming language
    - Their environment variables
    - Their container information

   This creates the so called initial process state. It's created when the k8s informers send the first pod information.
2. Beyla then registers with the k8 informers and starts receiving the new pod events, listing all
   existing pods. When the pod information comes we:
    - Discard any pods for nodes that don't belong to this current node where Beyla is running.
      This is important since Beyla typically is configured to see cluster wide information.
    - For each pod, consult the local process state. If matched we correlate the pod information with
      the process attributes, by the container ID, and then decide if this deployment should be 
      restarted, that is added to the eligible deployments. If it's an eligible deployment we write
      the config map state with this updated information. 
    - If we fail to find the process attributes we do a rebuild of the process state, while we
      haven't received all of the initial state from the k8s informers. Once all of the inital 
      k8s state is received we don't try to rebuild the local process state.
3. After the initial state is processed, new events from the k8s informers typically don't find 
   a thing, and we purely rely on the controller being there to add instrumentation.
4. The controller may be dead, not installed, or restarting, which posses a problem with our 
   statement in item 3. While the controller is inactive we have just seen new processes launch
   but when the controller will become active again, there's nobody to refresh the data in the
   eligible deployments config map. For this purpose, Beyla watches for new pod creations of the
   external controller. Beyla must be configured with the `namespace/deployment` of the external
   controller for this mode to be active. When Beyla sees a new pod created of the external 
   conroller it gets a new initial state and iterates over all current processes 
   to create a new eligible deployments map.
5. There's still a timing hole, because when we receive the last pod event from the newly starting
   controller, to the time the webhook is live inside the controller, there could be new pods
   launching. These pods will be missed, since we updated the eligible deployments prior to the
   webhook being live and instrumenting pods. We currently mititgate this with the debouncer pattern
   explained below. We delay the final recalculation of the eligible deployments by 10 seconds,
   which should be sufficient for the webhook to activate until the last update event of the 
   controller pod starting. If this doesn't work in the future, we need to find a way to signal
   from the controller that it's live.

Writing the config maps (same as for CRDs) requires involvement from `etcd` in Kubernetes. If
we were to constantly write this map, it will likely put too much pressure on the k8s 
infrastructure. For this reason we use a `debouncer` pattern, where we simply make a request for
the map to be written, and all that does is update a timestamp. There are background goroutines
which tick every seconds and watch for the timestamp being older than 10 seconds. Once we see
no new updates to the request to write timestamp, we write the config map and clear the timestamp.

The same debouncer pattern is used for the refresh of the eligible deployments. This is important
because the external controller can be scaled with a replica set, which means we'll get multiple 
new pod created events if the controller is redeployed. We want to build the new eligible deployments
when the dust has settled - so to speak.
