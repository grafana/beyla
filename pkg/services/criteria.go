package services

import (
	"reflect"
	"time"

	"gopkg.in/yaml.v3"

	"go.opentelemetry.io/obi/pkg/appolly/services"
)

const (
	k8sGKEDefaultNamespacesRegex = "|^gke-connect$|^gke-gmp-system$|^gke-managed-cim$|^gke-managed-filestorecsi$|^gke-managed-metrics-server$|^gke-managed-system$|^gke-system$|^gke-managed-volumepopulator$"
	k8sGKEDefaultNamespacesGlob  = ",gke-connect,gke-gmp-system,gke-managed-cim,gke-managed-filestorecsi,gke-managed-metrics-server,gke-managed-system,gke-system,gke-managed-volumepopulator"
)

const (
	k8sAKSDefaultNamespacesRegex = "|^gatekeeper-system"
	k8sAKSDefaultNamespacesGlob  = ",gatekeeper-system"
)

const (
	linuxSystem       = ",/sbin/*,/lib/systemd/*,/usr/lib/systemd/*,/lib/udev/*,/usr/lib/udev/*,*fusermount3,*ibus-daemon"
	linuxSystemDebian = ",/usr/lib/polkit-1/*,/usr/lib/policykit-1/*,/usr/lib/NetworkManager/*,/usr/lib/apt/*,/usr/lib/dpkg/*"
	linuxSystemRedhat = ",/usr/lib/rpm/*,/usr/libexec/sssd/*,/usr/libexec/udisks2/*,/usr/libexec/bluetooth/*,/usr/libexec/packagekitd*,/usr/libexec/accounts-daemon*,/usr/libexec/upowerd*,/usr/libexec/nm-*"
	linuxSystemSuse   = ",/usr/lib/wicked/*,/usr/lib/zypp/*,/usr/sbin/wickedd*,/usr/sbin/wickedd-nanny/*"
	linuxGUI          = ",/usr/libexec/gsd-*,/usr/libexec/gvfs*,/usr/libexec/gnome-*,/usr/libexec/ibus-*,/usr/libexec/xdg-{desktop-portal*,document-portal,permission-store},/usr/libexec/evolution-*,/usr/libexec/goa-*,/usr/libexec/at-spi*,/usr/libexec/{gdm-*,mutter-*},/usr/bin/update-notifier,/usr/lib/speech-dispatcher-modules*,/usr/libexec/xdg-*,*user-session-helper,*/gdm3,*/gcr-ssh-agent,*/switcheroo*,*/gnome-keyring-daemon,*/gjs,*/gjs-console"
	linuxPrint        = ",/usr/sbin/{cupsd,cups-browsed},/usr/lib/cups/*,/snap/cups/*"
	linuxCommon       = ",*/{sshd,udevadm,sshd-session,sshd-auth,ssh-agent},*/{cron,crond,anacron,atd},*/{chronyd,ntpd},*/{dbus-daemon,dbus-broker,dbus-broker-launch},*/{NetworkManager,ModemManager,wpa_supplicant,dhclient,dhcpcd},*/avahi-daemon,*/{polkitd,auditd},*/{packagekitd,snapd},*/{udisksd,upowerd},*/qemu-ga"
	linuxLogging      = ",*/{rsyslogd,syslog-ng,journald,systemd-journald}"
	linuxTimeSync     = ",*/{systemd-timesyncd,timesyncd}"
	linuxDNS          = ",*/{dnsmasq,systemd-resolved,named,unbound}"
	linuxFirewall     = ",*/{firewalld,nftables,iptables,ip6tables}"
	linuxVPN          = ",*/{openvpn,wireguard,tailscaled,wg-quick}"
	linuxMonitoring   = ",*/{node_exporter,cadvisor,fluentd,fluent-bit,vector,telegraf,datadog-agent,newrelic-infra}"
	linuxContainer    = ",*/{containerd,dockerd,crio,kubelet,kube-proxy,buildkitd,docker-compose,docker-proxy,docker}"
	linuxVirt         = ",*/{libvirtd,virtlogd,virtqemud,virtxend}"
	linuxSecurity     = ",*/{fail2ban,aide,tripwire}"
	linuxHardware     = ",*/{smartd,mdadm,multipathd,thermald,irqbalance,fwupd}"
	linuxShell        = ",*/{bash,zsh,dash,fish,tmux,screen,agetty,login,sudo,su,runuser,gnome-shell}"
	linuxCloudAWS     = ",/usr/bin/amazon-ssm-agent*,/usr/bin/ssm-agent-worker*,*/{ec2-instance-connect,amazon-cloudwatch-agent,aws-cfn-bootstrap,awslogs,aws-codedeploy-agent}"
	linuxCloudAzure   = ",/usr/sbin/waagent*,*/{azure-vm-agent,omsagent,mdsd,azuremonitoragent,azure-mdsd}"
	linuxCloudGCP     = ",*/{google-guest-agent,google-osconfig-agent,google-fluentd,ops-agent,google-cloud-ops-agent}"
	linuxCloudOther   = ",*/{oracle-cloud-agent,oci-utils,aliyun-service,ibm-cloud-agent,do-agent,droplet-agent}"
	linuxCloudInit    = ",*/{cloud-init,cloud-init-local,cloud-config,cloud-final}"
	linuxConfigMgmt   = ",*/{puppet,chef-client,salt-minion,salt-call,ansible,ansible-playbook}"
	linuxBackup       = ",*/{veeam,duplicity,bacula-fd,restic,borg}"
	linuxCompliance   = ",*/{osqueryd,falco,crowdsec,crowdsec-agent}"
	linuxPkgMgmt      = ",*/{unattended-upgrades,dnf-automatic,yum-cron,apt-daily,apt-daily-upgrade}"
	linuxMail         = ",*/{postfix,sendmail,exim,exim4,master,qmgr,pickup}"
	linuxAudio        = ",*/{wireplumber,pipewire,pipewire-pulse,pulseaudio,rtkit-daemon}"
	linuxDesktop      = ",*/{dconf,tracker-miner-fs-3,tracker-extract-*,tracker-miner-fs,tracker-store,dconf-service,gnome-calendar,gnome-shell,gnome-software,colord}"
	linuxPower        = ",*/{power-profiles-daemon,thermald,upowerd}"
	linuxSnap         = ",*/{snapd-desktop-integration,snapd,snap-confine}"
	linuxUbuntu       = ",*/{ubuntu-advantage-desktop-daemon,ubuntu-advantage-tools,ua,firmware-notifier}"
	linuxCrash        = ",*/{crashhelper,apport,whoopsie,kerneloops}"
	linuxSpeech       = ",*/{sd_openjtalk,speech-dispatcher,espeak,espeak-ng}"
	linuxVPNClient    = ",*/{nordvpnd,nordvpn,expressvpn,protonvpn,mullvad,norduserd}"
	linuxContainerd   = ",*/containerd-shim-*,*/containerd-shim-runc-*"
	linuxDisplay      = ",*/{Xwayland,Xorg,X,weston,sway,wayfire,labwc,river,hyprland,nautilus,seahorse}"
	linuxUtils        = ",*/{cat,sleep,snap,ls,cp,mv,rm,mkdir,rmdir,touch,chmod,chown,ln,dd,df,du,mount,umount,ps,kill,killall,top,htop,free,uptime,w,who,whoami,id,groups,su,sudo,passwd,chsh,chfn}"
	linuxDeleted      = ",*(deleted)"
	linuxMisc         = ",*/gopls,*/clangd,*/boltd"
	linuxKDE          = ",*/{plasmashell,kwin_x11,kwin_wayland,kded5,kded6,ksmserver,ksplashqml,plasma-discover,plasma-systemmonitor,kglobalaccel5,kglobalaccel6,kactivitymanagerd,kscreenlocker_greet,polkit-kde-authentication-agent-1,xdg-desktop-portal-kde,kdeconnectd,kdeconnect-indicator,korgac,akonadi_*}"
	linuxXFCE         = ",*/{xfce4-session,xfwm4,xfdesktop,xfce4-panel,xfce4-settings-helper,xfce4-power-manager,xfce4-notifyd,xfce4-screensaver,thunar,thunar-volman}"
	linuxLXQt         = ",*/{lxqt-session,lxqt-panel,lxqt-runner,lxqt-about,lxqt-policykit-agent,lxqt-notificationd,lxqt-powermanagement,lxqt-config,lxqt-config-appearance}"
	linuxLXDE         = ",*/{lxsession,lxpanel,pcmanfm,lxterminal,lxappearance,openbox}"
	linuxMATE         = ",*/{mate-session,mate-panel,mate-settings-daemon,mate-screensaver,mate-power-manager,caja,marco}"
	linuxCinnamon     = ",*/{cinnamon-session,cinnamon,cinnamon-settings-daemon,cinnamon-screensaver,nemo,muffin}"
	linuxPodman       = ",*/{podman,podman-compose,buildah,skopeo,crun,conmon,containers-common}"
)

var K8sDefaultNamespacesRegex = services.NewRegexp("^kube-system$|^kube-node-lease$|^local-path-storage$|^grafana-alloy$|^cert-manager$|^monitoring$" + k8sGKEDefaultNamespacesRegex + k8sAKSDefaultNamespacesRegex)
var K8sDefaultNamespacesGlob = services.NewGlob("{kube-system,kube-node-lease,local-path-storage,grafana-alloy,cert-manager,monitoring" + k8sGKEDefaultNamespacesGlob + k8sAKSDefaultNamespacesGlob + "}")

var K8sDefaultNamespacesWithSurveyRegex = services.NewRegexp("^kube-system$|^kube-node-lease$|^local-path-storage$|^cert-manager$" + k8sGKEDefaultNamespacesRegex + k8sAKSDefaultNamespacesRegex)
var K8sDefaultNamespacesWithSurveyGlob = services.NewGlob("{kube-system,kube-node-lease,local-path-storage,cert-manager" + k8sGKEDefaultNamespacesGlob + k8sAKSDefaultNamespacesGlob + "}")
var K8sDefaultExcludeContainerNamesGlob = services.NewGlob("{beyla,ebpf-instrument,obi,alloy,prometheus-config-reloader,otelcol,otelcol-contrib}")

var DefaultExcludeServices = services.RegexDefinitionCriteria{
	services.RegexSelector{
		Path: services.NewRegexp("(?:^|/)(beyla$|alloy$|prometheus-config-reloader$|otelcol[^/]*$)"),
	},
	services.RegexSelector{
		Metadata: map[string]*services.RegexpAttr{"k8s_namespace": &K8sDefaultNamespacesRegex},
	},
}
var DefaultExcludeServicesWithSurvey = services.RegexDefinitionCriteria{
	services.RegexSelector{
		Path: services.NewRegexp("(?:^|/)(beyla$|alloy$|prometheus-config-reloader$|otelcol[^/]*$)"),
	},
	services.RegexSelector{
		Metadata: map[string]*services.RegexpAttr{"k8s_namespace": &K8sDefaultNamespacesWithSurveyRegex},
	},
}

var DefaultExcludeInstrument = services.GlobDefinitionCriteria{
	services.GlobAttributes{
		Path: services.NewGlob("{*beyla,*alloy,*prometheus-config-reloader,*ebpf-instrument,*obi,*otelcol,*otelcol-contrib,*otelcol-contrib[!/]*}"),
	},
	services.GlobAttributes{
		Metadata: map[string]*services.GlobAttr{"k8s_namespace": &K8sDefaultNamespacesGlob},
	},
	services.GlobAttributes{
		Metadata: map[string]*services.GlobAttr{"k8s_container_name": &K8sDefaultExcludeContainerNamesGlob},
	},
}
var DefaultExcludeInstrumentWithSurvey = services.GlobDefinitionCriteria{
	services.GlobAttributes{
		Path: services.NewGlob("{*beyla,*alloy,*prometheus-config-reloader,*ebpf-instrument,*obi,*otelcol,*otelcol-contrib,*otelcol-contrib[!/]*" +
			linuxSystem + linuxSystemDebian + linuxSystemRedhat + linuxSystemSuse + linuxCloudAWS + linuxCloudAzure + linuxGUI + linuxPrint +
			linuxCommon + linuxLogging + linuxTimeSync + linuxDNS + linuxFirewall + linuxVPN + linuxMonitoring + linuxContainer + linuxVirt +
			linuxSecurity + linuxHardware + linuxShell + linuxCloudGCP + linuxCloudOther + linuxCloudInit +
			linuxConfigMgmt + linuxBackup + linuxCompliance + linuxPkgMgmt + linuxMail + linuxAudio + linuxDesktop + linuxPower +
			linuxSnap + linuxUbuntu + linuxCrash + linuxSpeech + linuxVPNClient + linuxContainerd + linuxDisplay + linuxUtils + linuxDeleted +
			linuxKDE + linuxXFCE + linuxLXQt + linuxLXDE + linuxMATE + linuxCinnamon + linuxPodman +
			linuxMisc +
			"}"),
	},
	services.GlobAttributes{
		Metadata: map[string]*services.GlobAttr{"k8s_namespace": &K8sDefaultNamespacesWithSurveyGlob},
	},
	services.GlobAttributes{
		Metadata: map[string]*services.GlobAttr{"k8s_container_name": &K8sDefaultExcludeContainerNamesGlob},
	},
}

type SurveyDefinitionCriteria []SurveySelector

// SurveySelector extends OBI's glob selection with additional survey specific criteria.
type SurveySelector struct {
	services.GlobAttributes `yaml:",inline"`

	// SocketApps requires observed socket activity for this survey selector.
	// Other matching survey selectors can admit the process without sockets.
	SocketApps bool `yaml:"socket_apps"`
}

// yaml.v3 doesn't propagate an inline map through an embedded inline struct.
// Expose the metadata map at the outer level so Kubernetes criteria survive
// both decoding and encoding the survey extension.
type surveySelectorFields SurveySelector

type surveySelectorYAML struct {
	Selector surveySelectorFields     `yaml:",inline"`
	Metadata services.MetadataGlobMap `yaml:",inline"`
}

func (s *SurveySelector) UnmarshalYAML(node *yaml.Node) error {
	var decoded surveySelectorYAML
	if err := node.Decode(&decoded); err != nil {
		return err
	}
	*s = SurveySelector(decoded.Selector)
	s.Metadata = decoded.Metadata
	return nil
}

func (s SurveySelector) MarshalYAML() (any, error) {
	return surveySelectorYAML{Selector: surveySelectorFields(s), Metadata: s.Metadata}, nil
}

func (s SurveyDefinitionCriteria) SocketAppsEnabled() bool {
	for i := range s {
		if s[i].SocketApps {
			return true
		}
	}
	return false
}

// DiscoveryConfig for the discover.ProcessFinder pipeline
type BeylaDiscoveryConfig struct {
	// Services selection. If the user defined the BEYLA_EXECUTABLE_NAME or BEYLA_OPEN_PORT variables, they will be automatically
	// added to the services definition criteria, with the lowest preference.
	//
	// Deprecated: Use Instrument instead
	Services services.RegexDefinitionCriteria `yaml:"services"`

	// Survey selection. Same as services selection, however, it generates only the target info (survey_info) instead of instrumenting the services
	Survey SurveyDefinitionCriteria `yaml:"survey"`

	// ExcludeServices works analogously to Services, but the applications matching this section won't be instrumented
	// even if they match the Services selection.
	//
	// Deprecated: Use ExcludeInstrument instead
	ExcludeServices services.RegexDefinitionCriteria `yaml:"exclude_services"`

	// DefaultExcludeServices by default prevents self-instrumentation of Beyla as well as related services (Alloy and OpenTelemetry collector)
	// It must be set to an empty string or a different value if self-instrumentation is desired.
	//
	// Deprecated: Use DefaultExcludeInstrument instead
	DefaultExcludeServices services.RegexDefinitionCriteria `yaml:"default_exclude_services"`

	// Instrument selects the services to instrument via Globs. If this section is set,
	// both the Services and ExcludeServices section is ignored.
	// If the user defined the BEYLA_AUTO_TARGET_EXE or BEYLA_OPEN_PORT variables, they will be
	// automatically added to the instrument criteria, with the lowest preference.
	Instrument services.GlobDefinitionCriteria `yaml:"instrument"`

	// ExcludeInstrument works analogously to Instrument, but the applications matching this section won't be instrumented
	// even if they match the Instrument selection.
	ExcludeInstrument services.GlobDefinitionCriteria `yaml:"exclude_instrument"`

	// DefaultExcludeInstrument by default prevents self-instrumentation of OBI as well as related services (Beyla, Alloy and OpenTelemetry collector)
	// It must be set to an empty string or a different value if self-instrumentation is desired.
	DefaultExcludeInstrument services.GlobDefinitionCriteria `yaml:"default_exclude_instrument"`

	// PollInterval specifies, for the poll service watcher, the interval time between
	// process inspections
	PollInterval time.Duration `yaml:"poll_interval" env:"BEYLA_DISCOVERY_POLL_INTERVAL"`

	// This can be enabled to use generic HTTP tracers only, no Go-specifics will be used:
	SkipGoSpecificTracers bool `yaml:"skip_go_specific_tracers" env:"BEYLA_SKIP_GO_SPECIFIC_TRACERS"`

	// Debugging only option. Make sure the kernel side doesn't filter any PIDs, force user space filtering.
	BPFPidFilterOff bool `yaml:"bpf_pid_filter_off" env:"BEYLA_BPF_PID_FILTER_OFF"`

	// Disables instrumentation of services which are already instrumented
	ExcludeOTelInstrumentedServices bool `yaml:"exclude_otel_instrumented_services" env:"BEYLA_EXCLUDE_OTEL_INSTRUMENTED_SERVICES"`

	// DefaultOtlpGRPCPort specifies the default OTLP gRPC port (4317) to fallback on when missing environment variables on service, for
	// checking for grpc export requests, defaults to 4317
	DefaultOtlpGRPCPort int `yaml:"default_otlp_grpc_port" env:"BEYLA_DEFAULT_OTLP_GRPC_PORT"`

	// Min process age to be considered for discovery.
	MinProcessAge time.Duration `yaml:"min_process_age" env:"BEYLA_MIN_PROCESS_AGE"`

	// ProcessContextPollInterval controls how often Beyla re-reads the OTEL_CTX
	// mapping of each discovered process.  Polling handles both SDKs that
	// publish the mapping after startup and context updates published later.
	// 0 disables polling; only the initial enrichment on process creation runs.
	ProcessContextPollInterval time.Duration `yaml:"process_context_poll_interval" env:"BEYLA_PROCESS_CONTEXT_POLL_INTERVAL"`

	// Disables generation of span metrics of services which are already instrumented
	ExcludeOTelInstrumentedServicesSpanMetrics bool `yaml:"exclude_otel_instrumented_services_span_metrics" env:"BEYLA_EXCLUDE_OTEL_INSTRUMENTED_SERVICES_SPAN_METRICS"`

	RouteHarvesterTimeout time.Duration `yaml:"route_harvester_timeout" env:"OTEL_EBPF_ROUTE_HARVESTER_TIMEOUT"`

	DisabledRouteHarvesters []services.RouteHarvesterLanguage `yaml:"disabled_route_harvesters"`

	RouteHarvestConfig RouteHarvestingConfig `yaml:"route_harvester_advanced"`

	// Executable paths for which we don't run language detection and cannot be
	// selected using the path or language selection criteria
	ExcludedLinuxSystemPaths []string `yaml:"excluded_linux_system_paths"`
}

type RouteHarvestingConfig struct {
	JavaHarvestDelay time.Duration `yaml:"java_harvest_delay" env:"OTEL_EBPF_JAVA_ROUTE_HARVEST_DELAY"`
}

func (d *BeylaDiscoveryConfig) SurveyEnabled() bool {
	return len(d.Survey) > 0
}

func (d *BeylaDiscoveryConfig) OverrideDefaultExcludeForSurvey() {
	if reflect.DeepEqual(d.DefaultExcludeServices, DefaultExcludeServices) &&
		reflect.DeepEqual(d.DefaultExcludeInstrument, DefaultExcludeInstrument) {
		d.DefaultExcludeServices = DefaultExcludeServicesWithSurvey
		d.DefaultExcludeInstrument = DefaultExcludeInstrumentWithSurvey
	}
}

func (d *BeylaDiscoveryConfig) AppDiscoveryEnabled() bool {
	return len(d.Services) > 0 || len(d.Instrument) > 0
}
