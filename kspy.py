from kazoo.client import KazooClient
from kafka import SimpleConsumer, KafkaClient
import argparse

if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="Spy on kafka topics")
    parser.add_argument('--partition', dest="partition", type=str, required=True, help="Partition to read")
    parser.add_argument('--offset', dest="offset", type=str, required=False, help="Offset to read")
    parser.add_argument('--topic', dest="topic", type=str, required=True, help="Kafka topic")
    parser.add_argument('--consumer', dest="consumer", type=str, required=True, help="Consumer group name")
    # parser.add_argument('--group', dest="group", type=str, required=True, help="offset to read")
    parser.add_argument('--zk', dest="zk", type=str, default="", required=True, help="Zookeeper:port")
    parser.add_argument('--broker', dest="broker", type=str, default="", required=True, help="kafkabroker:port")
    parser.add_argument('--set', dest="set", action="store_true", help="Set the offset to the value you gave in --offset")

    args = parser.parse_args()

    zk = KazooClient(hosts="%s" % (args.zk))
    zk.start()

    data, stats = zk.get('/consumers/{0}/offsets/{1}/{2}'.format(args.consumer, args.topic, args.partition))
    old_offset = data.decode()

    if args.offset:
        zk.set('/consumers/{0}/offsets/{1}/{2}'.format(args.consumer, args.topic, args.partition), b"%s" % (args.offset))

    try:
        if args.broker:
            kclient = KafkaClient("%s" % (args.broker))

            # add support for more than 1 parititon
            consumer = SimpleConsumer(kclient, args.consumer, args.topic, partitions=[0])
            consumer.max_buffer_size = None
            if args.offset:
                consumer.seek(0, 1)

            message = consumer.get_message()
            if message:
                print "DEBUG: restoring"
                print("MSG: " + str(message[1][3]) + "\tOFFSET: " + str(message[0]) + "\t KEY: " + str(message.message.key) )

        if not args.set:
            zk.set('/consumers/{0}/offsets/{1}/{2}'.format(args.consumer, args.topic, args.partition), b"%s" % (old_offset))
        else:
            print "Old offset %s" % (old_offset)
            print "New offset %s" % (args.offset)
    except:
        # zk.set('/consumers/{0}/offsets/{1}/{2}'.format(args.consumer, args.topic, args.partition), b"%s" % (old_offset))
        pass

