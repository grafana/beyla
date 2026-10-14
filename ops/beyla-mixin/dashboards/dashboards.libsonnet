{
  grafanaDashboardFolder+: 'beyla',
  grafanaDashboards+: {
    'beyla_debug.json': (import './beyla_debug.json') {
      uid: std.md5('beyla_debug.json'),
    },
    'application.json': (import './application.json') {
      uid: std.md5('application.json'),
    },
    // TODO: Include this dashboard only if application_process is enabled
    'application_process.json': (import './application_process.json') {
      uid: std.md5('application_process.json'),
    },    
  },
}