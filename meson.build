project('dpdk-perf', 'c',
  version: '0.0.1',
  default_options: ['warning_level=3', 'c_std=c11'])

dpdk_dep = dependency('libdpdk', method: 'pkg-config', required: true)

add_project_arguments('-D_POSIX_C_SOURCE=200809L', language: 'c')
add_project_arguments('-Wpedantic', language: 'c')

sources_ping = files('ping.c',
  'packet.c',
  'port.c',
  'util.c')
sources_pong = files('pong.c',
  'packet.c',
  'port.c',
  'util.c')

executable('dpdk-ping', sources_ping, dependencies: dpdk_dep)
executable('dpdk-pong', sources_pong, dependencies: dpdk_dep)

