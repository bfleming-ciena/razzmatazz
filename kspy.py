from kazoo.client import KazooClient
from kafka import SimpleConsumer, KafkaClient
import argparse

if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="Spy on kafka topics")
    parser.add_argument('--partition', dest="partition", type=str, required=True, help="partition")
    parser.add_argument('--offset', dest="offset", type=str, required=False, help="offset to read")
    parser.add_argument('--topic', dest="topic", type=str, required=True, help="offset to read")
    parser.add_argument('--consumer', dest="consumer", type=str, required=True, help="offset to read")
    parser.add_argument('--kafka', dest="kafka", action='store_true', help="offset to read")
    # parser.add_argument('--group', dest="group", type=str, required=True, help="offset to read")
    parser.add_argument('--value', dest="value", type=str, default="", help="not-used")
    parser.add_argument('--zk', dest="zk", type=str, default="", required=True, help="not-used")
    parser.add_argument('--broker', dest="broker", type=str, default="", required=True, help="not-used")

    args = parser.parse_args()

    zk = KazooClient(hosts="%s" % (args.zk))
    zk.start()

    data, stats = zk.get('/consumers/{0}/offsets/{1}/{2}'.format(args.consumer, args.topic, args.partition))
    print "Current value {0}".format(data.decode())

    if(args.value):
        zk.set('/consumers/{0}/offsets/{1}/{2}'.format(args.consumer, args.topic, args.partition), b"%s" % (args.value))

    if args.broker:
        kclient = KafkaClient("%s" % (args.broker))

        # add support for more than 1 parititon
        consumer = SimpleConsumer(kclient, args.consumer, args.topic, partitions=[0])
        consumer.max_buffer_size = None
        consumer.seek(0, 1)
        print consumer.get_message()
