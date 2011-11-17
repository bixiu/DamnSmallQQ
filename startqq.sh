 #!/bin/sh 
   
while true
	do 
		echo "Check if qq is running..."
		i=`ps aux | grep qq | grep -v grep | wc -l` 
		if   [   "$i"   =   "0"  -o "$i" =  "      0" ];   then  
			echo   "qq is not running, start it..."    
			date >> deamon.log
			ulimit -c unlimited
			./qq     
		else  
			echo   "qq is running"  
		fi 
		sleep   60
	done 
   
 
