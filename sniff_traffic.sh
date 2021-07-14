#!/bin/bash
source /home/lyx/anaconda3/etc/profile.d/conda.sh
conda deactivate

cd /home/lyx/PycharmProjects/IconChecker/
apk_path=$1  # input apk's path
home_path=/home/lyx/Desktop/auto
echo "decoded apk......"
python3 decode.py --apk_path $apk_path
iterations=4

for dirname in $(ls $apk_path)
do
    name=${dirname%.*}
    if [ -f "/home/lyx/Desktop/decoded/$name/AndroidManifest.xml" ]
    then
        for iteration in $(seq 1 $iterations)
        do
            echo "start $dirname..."
            name=${dirname%.*}
            echo "extrat traffic......"
            echo $apk_path$dirname
            python3 sniff_traffic2.py --manifestname /home/lyx/Desktop/decoded/$name/AndroidManifest.xml --apk_name $apk_path$dirname
            a=`awk '{for(i=1;i<=NF;i++)printf $i"\n";printf "\n"}' /home/lyx/Desktop/decoded/$name/AndroidManifest.xml | grep "package=\"" |awk -F= '{print $2}'`
            packagename=$(echo $a | awk -F '"' '{print $2}')  

            if [ ! -d "$home_path/$name/" ]
            then
                echo "finish $dirname..."
                break
            else
                if [ ! -f "$home_path/$name/image_id_semantics_text.csv" ]
                then
                    echo "***********************************************"
                    # rm -rf $home_path/$name/
                    break
                fi
        
                echo "filter traffic......"
                python3 filter.py --input $home_path/$name/ori/ --output $home_path/$name/filter/ --ports $home_path/$name/ports/
    
                echo "finish $dirname..."
                mv $home_path/1006/$name/$name $home_path/1006/$name/$name$iteration
            fi
        done
        echo "Cross Checking......"
        python3 CrossCheck.py --apkname $name --homepath $home_path

        echo "Analysis..., and create a report."
        conda activate sift
        cd /home/lyx/PycharmProjects/SIFT_new/
        python id_semantics.py --path $home_path/1006/ --packagename $name
        python result_noSIFT.py --packagename $name
        echo "Finish Analysis $packagename ..."
        conda deactivate
        cd /home/lyx/PycharmProjects/IconChecker/
    else
        echo "Decoded $dirname Error..."
    fi   
done

echo "******done******"
