port=2223
if nc -z 0.0.0.0 $port; then
   echo "Порт $port занят"
else
   echo "Порт $port свободен"
fi
