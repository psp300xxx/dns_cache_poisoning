import threading
import time
def test(is_finished):
    while not is_finished[0]:
        time.sleep(1)
        print("sleeping")
    print("finished")

global is_finished
is_finished = [False]
t1 = threading.Thread(target=test, args=(is_finished,))
t1.start()
time.sleep(5)
is_finished[0] = True
time.sleep(5)