for i in $(seq 1 2)
do
echo $i	
#am start -n com.example.svqsee/.MainActivity

sleep 2

#am force-stop com.example.svqsee
./data/local/tmp/extract_keymaster
done

#setprop wrap.com.example.svqsee LD_PRELOAD=/data/local/tmp/libQSEEComAPI.so 
#am start -n com.example.svqsee/.MainActivity
