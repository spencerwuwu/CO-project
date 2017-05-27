#!/bin/sh
make clean
make riscv
touch result.tmp
echo "Compile success, start running"
make riscv-run > result.tmp


if [ "$(grep -r "Sorry" result.tmp)" != "" ]
then
	echo "Wrong result"
else
	D_Access1="$(cat result.tmp | sed -n '4p' | sed -e "s/\s\{3,\}/ /g" | awk -F ":" '{ print $2 }')"
	D_Access2="$(cat result.tmp | sed -n '5p' | sed -e "s/\s\{3,\}/ /g" | awk -F ":" '{ print $2 }')"
	D_amat="$(cat result.tmp | sed -n '9p' | sed -e "s/\s\{3,\}/ /g" | awk -F ":" '{ print ($2*2+1) }')" 

	I_Access1="$(cat result.tmp | sed -n '12p' | sed -e "s/\s\{3,\}/ /g" | awk -F ":" '{ print $2 }')"
	I_Access2="$(cat result.tmp | sed -n '13p' | sed -e "s/\s\{3,\}/ /g" | awk -F ":" '{ print $2 }')"
	I_amat="$(cat result.tmp | sed -n '17p' | sed -e "s/\s\{3,\}/ /g" | awk -F ":" '{ print ($2*2+1) }')" 

	echo "D1 AMAT = $D_amat"
	echo -n "D1 total cache access time = "
	echo $(python -c "print($D_amat * ($D_Access1+$D_Access2))")
	echo "I1 AMAT = $I_amat"
	echo -n "I1 total cache access time = "
	echo $(python -c "print($I_amat * ($I_Access1+$I_Access2))")
fi

echo "*************************************************************"
echo ""
rm result.tmp
