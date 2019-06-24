for j in `ls *.c`; do
	echo "Compiling "$j;
	gcc $j -o ${j%.*}.bin;
done

