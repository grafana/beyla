// Custom Beyla image build (ShareChat) — adds [TPHDR] traceparent-extraction
// logging on top of upstream Beyla v3.22.2 (OBI v3.20.0).
//
// The code change lives as a patch in patches/ (the .obi-src submodule points at
// grafana upstream and is not pushable), applied to .obi-src at build time. The
// repo Dockerfile is self-contained (multi-stage: obi-generator -> go build), so
// a plain `docker build` regenerates eBPF and compiles the patched Go.
pipeline {
  agent {
    kubernetes {
      label 'beyla-custom'
      yaml """
apiVersion: v1
kind: Pod
spec:
  containers:
  - name: dind
    image: sc-mum-armory.platform.internal/devops/dind:v2
    securityContext:
      privileged: true
    env:
    - name: DOCKER_HOST
      value: tcp://localhost:2375
    - name: DOCKER_TLS_CERTDIR
      value: ""
    volumeMounts:
      - name: dind-storage
        mountPath: /var/lib/docker
    readinessProbe:
      tcpSocket:
        port: 2375
      initialDelaySeconds: 30
      periodSeconds: 10
  - name: builder
    image: sc-mum-armory.platform.internal/devops/builder-image-armory
    command:
    - sleep
    - infinity
    env:
    - name: DOCKER_HOST
      value: tcp://localhost:2375
    - name: DOCKER_BUILDKIT
      value: "1"
    volumeMounts:
      - name: jenkins-sa
        mountPath: /root/.gcp/
  volumes:
    - name: dind-storage
      emptyDir: {}
    - name: jenkins-sa
      secret:
        secretName: jenkins-sa
"""
    }
  }

  environment {
    REGISTRY  = "sc-mum-armory.platform.internal"
    IMAGE     = "sharechat/beyla-custom"
    IMAGE_TAG = "v3.22.2-tphdr-debug"
  }

  stages {
    stage('build') {
      when {
        anyOf {
          branch 'tphdr-debug-logging'
          branch 'master'
        }
      }
      steps {
        container('builder') {
          sh '''
            set -euo pipefail
            git config --global --add safe.directory '*'

            # Pull the OBI submodule (.obi-src) at the pinned upstream commit,
            # then apply the ShareChat patch (traceparent-extraction logging).
            git submodule update --init --recursive
            ( cd .obi-src && git apply --verbose ../patches/0001-tphdr-traceparent-logging.patch )

            # Build the self-contained upstream Dockerfile (handles eBPF generation
            # via the obi-generator stage + compiles the patched .obi-src).
            docker build --build-arg BUILDARCH=amd64 \
              -t ${REGISTRY}/${IMAGE}:${IMAGE_TAG} .
          '''
        }
      }
    }

    stage('push') {
      when {
        anyOf {
          branch 'tphdr-debug-logging'
          branch 'master'
        }
      }
      steps {
        container('builder') {
          sh '''
            set -euo pipefail
            docker push ${REGISTRY}/${IMAGE}:${IMAGE_TAG}
          '''
        }
      }
    }
  }
}
