from kafka import SimpleConsumer, KafkaClient
# more advanced consumer -- multiple topics w/ auto commit offset
# management

import sys

kclient = KafkaClient("52.24.239.65:9092")


consumer = SimpleConsumer(kclient, "bf-group", sys.argv[1], partitions=[0,1])
consumer.max_buffer_size=None


consumer.seek(0,1)

while True:
    for message in consumer.get_messages():
        print("OFFSET: "+str(message[0])+"\t MSG: "+str(message[1][3]) + "KEY: " + str(message.message.key) )


sys.exit(0)


client = KafkaClient(['52.24.239.65:9092'], client_id='bfleming')
consumer = SimpleConsumer(client, "bfleming", 'bfleming00615')

print consumer.get_messages(count=10)
                         # auto_offset_reset='smallest')
import ipdb
ipdb.set_trace()
# Infinite iteration
# for m in consumer:
    # print m
    # consumer.task_done(m)
# do_some_work(m)

# Mark this message as fully consumed
# so it can be included in the next commit
#
# **messages that are not marked w/ task_done currently do not commit!
# consumer.task_done(m)

# If auto_commit_enable is False, remember to commit() periodically
# consumer.commit()

# Batch process interface
while True:
    for m in consumer.fetch_messages():
        # process_message(m)
        print m
        print consumer.offsets()
        import ipdb
        ipdb.set_trace()
        # consumer.task_done(m)
        # consumer.commitOffsets(true)