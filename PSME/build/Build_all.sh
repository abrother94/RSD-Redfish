#!/bin/bash
rm ../agent/storage/include/storage_config.hpp
rm -rf ../application/include/psme/rest/metadata/include-generated/
rm ../application/include/version.hpp
rm ../common/agent-framework/include/agent-framework/version.hpp

mv pre-inst-X86-pkgs.sh ../
mv psme_release.sh ../
mv Build_all.sh ../
mv Build_ONL.sh ../
mv Build_BAL_SDK_ALL.sh ../
cd ../
rm -rf build/*
mv pre-inst-X86-pkgs.sh build
mv psme_release.sh build
mv Build_all.sh build
mv Build_ONL.sh build  
mv Build_BAL_SDK_ALL.sh build
cd build

if [ "$1" != "C" ];then
    echo "Build all"
    if [ "$0" == "bal26" ];then
	echo "Build for bal sdk 2.6 platform!"
	cp ../CMakeLists.txt ../CMakeLists.txt-org
	`sed -i 's/-DONLP)/-DVOLT -DBCMOS_MSG_QUEUE_DOMAIN_SOCKET -DBCMOS_MSG_QUEUE_UDP_SOCKET -DBCMOS_MEM_CHECK &\nset(CUSE_ACC_BAL_DISTLIB "TRUE")/' ../CMakeLists.txt`
    elif [ "$1" == "bal30" ];then
	echo "Build for bal sdk 3.0 platform!"
	cp ../CMakeLists.txt ../CMakeLists.txt-org
	`sed -i 's/-DONLP)/-DBCMOS_MSG_QUEUE_DOMAIN_SOCKET -DBCMOS_MSG_QUEUE_UDP_SOCKET -DBCMOS_MEM_CHECK  -DBCMOS_SYS_UNITTEST -DENABLE_LOG -DENABLE_CLI &\nset(CUSE_ACC_BAL3_DISTLIB "TRUE")/' ../CMakeLists.txt`
    elif [ "$1" == "bal31" ];then
	echo "Build for bal sdk 3.1 platform!"
	cp ../CMakeLists.txt ../CMakeLists.txt-org
	`sed -i 's/-DONLP)/-DBAL31 -DBCMOS_MSG_QUEUE_DOMAIN_SOCKET -DBCMOS_MSG_QUEUE_UDP_SOCKET -DBCMOS_MEM_CHECK  -DBCMOS_SYS_UNITTEST -DENABLE_LOG -DENABLE_CLI &\nset(CUSE_ACC_BAL3_DISTLIB "TRUE")/' ../CMakeLists.txt`
    elif [ "$1" == "bal32" ];then
	echo "Build for bal sdk 3.2 platform!"
	cp ../CMakeLists.txt ../CMakeLists.txt-org
	`sed -i 's/-DONLP)/-DBAL32 -DBCMOS_MSG_QUEUE_DOMAIN_SOCKET -DBCMOS_MSG_QUEUE_UDP_SOCKET -DBCMOS_MEM_CHECK  -DBCMOS_SYS_UNITTEST -DENABLE_LOG -DENABLE_CLI &\nset(CUSE_ACC_BAL3_DISTLIB "TRUE")/' ../CMakeLists.txt`
    elif [ "$1" == "bal34" ];then
	echo "Build for bal sdk 3.4 platform!"
	cp ../CMakeLists.txt ../CMakeLists.txt-org
	`sed -i 's/-DONLP)/-DBAL34 -DBCMOS_MSG_QUEUE_DOMAIN_SOCKET -DBCMOS_MSG_QUEUE_UDP_SOCKET -DBCMOS_MEM_CHECK  -DBCMOS_SYS_UNITTEST -DENABLE_LOG -DENABLE_CLI &\nset(CUSE_ACC_BAL3_DISTLIB "TRUE")/' ../CMakeLists.txt`
    fi

    cmake ../
    grep -rl Werror . | grep flags.make | xargs sed -i 's/-Werror//g'
    #make unittest_psme-chassis_onlp
    #make unittest_psme-chassis_acc_api_bal_dist_test 
    #make unittest_psme-chassis_acc_api_bal3_dist_test 
    make all 2>&1 | tee  onl.log    
    find ./ -name control  | xargs sed -i 's/armel/amd64/g'
    find ../tools/deb_maker/install/allinone-deb/psme-allinone/DEBIAN -name control  | xargs sed -i 's/armel/amd64/g'
    ./psme_release.sh
    cp ../CMakeLists.txt-org ../CMakeLists.txt
    rm ../CMakeLists.txt-org
fi
