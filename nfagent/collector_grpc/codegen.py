from grpc.tools import protoc

protoc.main(
    (
        '',
        '-I.',
        '--python_out=.',
        '--grpc_python_out=.',
        '--proto_path=../../api/',
        '../../api/packet_collector.proto',
    )
)
