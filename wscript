def build(bld):
    module = bld.create_ns3_module('tesla', ['core', 'network', 'internet',
                                             'applications', 'point-to-point',
                                             'csma', 'netanim'])
    module.source = [
        'model/tesla-protocol.cc',
    ]

    # Link OpenSSL libraries
    module.use.append('CRYPTO')
    module.use.append('SSL')

    headers = bld(features='ns3header')
    headers.module = 'tesla'
    headers.source = [
        'model/tesla-protocol.h',
    ]
    if bld.env.ENABLE_EXAMPLES:
       bld.recurse('examples')

def configure(conf):
    # Check for OpenSSL
    conf.check_cc(lib='crypto', mandatory=True, uselib_store='CRYPTO')
    conf.check_cc(lib='ssl', mandatory=True, uselib_store='SSL')