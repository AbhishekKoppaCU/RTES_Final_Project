project('packet_logger', 'c')

dpdk_dep = dependency('libdpdk', required: true)

executable('packet_logger',
  'main.c',
  dependencies: dpdk_dep,
  install: false
)
