for i in $(ps aux | grep dns_attack.py); do
	kill -9 $i
done
