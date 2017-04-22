#include "bmp.h"

#define numOutput 4
#define diffLimit 4000

char *outputNames[numOutput] = {
	"Output/blurObsceneBug.bmp",
	"Output/blurDeeHuiGray.bmp",	
	"Output/LoGObsceneBug.bmp",
	"Output/LoGDeeHuiGray.bmp"
};

char *goldenOutputNames[numOutput] = {
	"GoldenOutput/blurObsceneBug.bmp",
	"GoldenOutput/blurDeeHuiGray.bmp",	
	"GoldenOutput/LoGObsceneBug.bmp",
	"GoldenOutput/LoGDeeHuiGray.bmp"
};

int check(BMP *bmptr1, BMP *bmptr2)
{
	BYTE byte1, byte2;
	int i, size;
	int count = 0;

	size = bmptr1->height*bmptr2->width*3;

	for(i = 0; i < size; i++){
		byte1 = bmptr1->data[i*sizeof(BYTE)];
		byte2 = bmptr2->data[i*sizeof(BYTE)];
		if(byte1 != byte2)
			count++;
	}

	return count;
}

int main()
{
	BMP bmp1, bmp2;
	int i, diffCount;
	int pass = 1;

	for(i = 0; i < numOutput; i++){
		diffCount = 0;
		bmpLoad(&bmp1, outputNames[i]);
		bmpLoad(&bmp2, goldenOutputNames[i]);
		diffCount = check(&bmp1, &bmp2);
		if(diffCount > diffLimit){
			pass = 0;
			break;
		}	
	}

	if(pass == 0){
		printf("\033[90m@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@88OCCoccccc ccooOO8@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n");
printf("\033[90m@@@@@@@Oc@@c\033[32m@@@@@@\033[0;90mo@O\033[32m@@@@@@@\033[0;90m@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@Oc                  c              \033[90mcO@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n");
printf("\033[90m@@@@@@@\033[32m@@\033[0;90m@@@8@@@\033[32m@@@\033[0;90m@@8O8@c\033[32m@@\033[0;90m@@@@@@@@@@@@@@@@@@@@                             \033[93mcooO888OCCCCCCCCCCCOOOOOCCCCCCc         \033[90mcoOO@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n");
printf("\033[90m@@@@@8\033[32m@@\033[0;90mo@@o\033[32m@\033[0;90mc@@C\033[32m@@\033[0;90m@@@@OC\033[32m@@@\033[0;90m@@@@@@@@@@@@@@@@@@@c  \033[31mcOOOOOOOOOO88o      \033[93mcoCCCCCCCOOOOOOOOCCCCCCCOOOOOOOOOCCCCCCCCOOOo                        \033[90mc@@@@@@@@@@\n");
printf("\033[90m@@@@8\033[32m@@\033[0;90mo@@@C\033[32m@@@@@@@\033[0;90m@@c\033[32m@@@@@\033[0;90mo@@@@@@@@@@@@@@@@@@o  \033[31mO  8OOOOO8o     \033[93moO8OOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO8Oo     \033[31mo888OOCCCocc    \033[90mO@@@@@@@@\n");
printf("\033[90m@@@c\033[32m@@@\033[0;90mo@@@O\033[32m@@\033[0;90m@@8OO@@@@@@@@@@@@@@@@@@@@@@@@@@O  \033[31mCCOc C8Oc     \033[93moOO88OOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO888CCccc   \033[93mcc     \033[31mO8OOOO8  Cc  \033[90m@@@@@@@@\n");
printf("\033[90m@\033[32m@@@o\033[0;90mo\033[32m@@\033[0;90m@@@8\033[32m@@@@@@@@\033[0;90m@O\033[32m@@@@@@@\033[0;90m@@@@@@@@@@@@@@@@  \033[31mcOCCOc                \033[93mcCO8OOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO8OOo               \033[93mcO8O    \033[31mcO8o cOCO  \033[90mo@@@@@@@\n");
printf("\033[90m@@@@@C\033[32m@@\033[0;90m@@@@\033[32m@@\033[0;90mC@8OoO@@o@@O\033[32m@@\033[0;90mC@@@@@@@@@@@@@@@   \033[31m8OCO    \033[93mo8OO8OOOOOCCoocc   COOOOOOOOOOOOOOOOOOOOOOOOOOOc      \033[93mccccooCCCCOCCOOOOOO8O     \033[31mCCCCOo  \033[90m8@@@@@@\n");
printf("\033[90m@@@@@C\033[32m@@\033[0;90m@@@@\033[32m@@@@@@@\033[0;90mo@@c\033[32m@@@@\033[0;90mo@@@@@@@@@@@@@@@O  \033[31mCOOO   \033[93m8OOOO8OOOOOOO8888OOOOOOOOOOOOOOOOOO\033[0m@@\033[93mOOOOOOOOOOOOOOOOOOO8O8O88O8OOOOOOOOOOOOOO8o   \033[31mcOCCOc \033[90mc@@@@@@\n");
printf("\033[90m@@@@@O\033[32m@@\033[0;90mO@@@\033[32m@@@\033[0;90m@@@@@@@C\033[32m@@@@@@@@\033[0;90m@@@@@@@@@@@@  \033[31mc8O  \033[93mc8OO8C\033[0m           cCc \033[93mc8OOOOOOOOOOOOO\033[0m@@@@@@\033[93mOOOOOOOOOOOO8C\033[0m               o\033[93m88OOOOOOOOO8C   \033[31mo8OC  \033[90m8@@@@@\n");
printf("\033[90m@@@@@@\033[32m@@\033[0;90m8@@@c\033[32m@@\033[0;90m@@@@@@@\033[32m@@\033[0;90mC@@@@@@@@@@@@@@@@@o  \033[31m8c   \033[93mO8C\033[0m O@@O          @@@@o \033[93m8OOOO888O8\033[0m@@@@@@@@@@\033[93m8OOOOOOO8\033[0m o@@@          O@@@8C\033[93m C8OOOOOOOOOC   \033[31mO8  \033[90mc@@@@@\n");
printf("\033[990m@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@  \033[31mc   \033[93mOO8o\033[0mc@@@@o          8@@@@ \033[93mOO8 \033[94m oCc\033[0m O@@@@@@@@@@@\033[94mo  \033[93mcOO8\033[0m c@@@O          O@@@@@@C\033[93mc8OOOOOOOOO8c  \033[31mcO  \033[90m@@@@@\n");
printf("\033[90m@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@c    \033[93mc8OOO 8\033[0mo@@@8          @8C  \033[93m8OO \033[94m@@@@@@c\033[0mo8oc  cC8 \033[94mo@@@@\033[0;93mCCO8\033[0m  O@@          O@@@@@@ \033[93mC8OOOOOOOOOOOO     \033[90mc@@@@\n");
printf("\033[90m@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@8    \033[93mCOOOOOOOO8c\033[0m         cco\033[93mO88OO8@o\033[94mo@@@@@@C\033[36m @@@@@@@o\033[0;94mo@@@@@@\033[0m @\033[93m8OO8Occ\033[0m         Coc   \033[93mOOOOOOOOOOOOOOOO8     \033[90m8@@@\n");
printf("\033[90m@@@@@@@@@@@O8@@@@@@@\033[32mo@C\033[0;90m@@@@@@@@@@@@@@@@@C   \033[93mOOOOOOOOOOOOOOOOOOOOOOOOOO\033[0m8@@@@@ \033[94mO8OOC8\033[0m OC    c8@ \033[94m8@@@@@\033[0m @@@@@\033[93m8OO8OOOO888888O8OOOOOOOOOOOOOOOOOOO8c   \033[90mC@@@\n");
printf("\033[90m@@@@@@@@@@\033[32m@@@\033[0;90m@@@@@@@\033[32mc@c\033[0;90m@@@@@@@@@@@@@@@@@   \033[93mOOOOOOOOOOOOOOOOOOOOOOOO\033[0m8@@@@@@C   C8@@@O         coo    @@@@@@@@@\033[93m8OOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO8c  \033[90mc@@@\n");
printf("\033[90m@@@@@@@@@\033[32m@@@\033[0;90m@@@@@@@@\033[32m@@@@@@@@@@\033[0;90mO@@@@@@@@o  \033[93mO8OOOOOOOOOOOOOOOOOOOO\033[0m8@@@@@@@O o@@@@@@@@@@       8@@@@@@@  @@@@@@@@@@\033[93m8OOOOOOOOOOOOOOOOOOOOOOOOOOOOOO8c  \033[90m@@@\n");
printf("\033[90m@@@@@@@C\033[32m@@\033[0;90mo@@@@@@@@@\033[32m@@\033[0;90mC@@@@@\033[32m@@@\033[0;90m@@@@@@@o  \033[93mOOOOOOOOOOOOOOOOOOO\033[0m8@@@@@@@@@@ o@@@@@@@@@@@@ o@@@@@@@@@@@@@@@c @@@8c@@@@@@@\033[93m8OOOOOOOOOOOOOOOOOOOOOOOOOOO8c  \033[90m8@\n");
printf("\033[90m@@@@@@C\033[32m@@@@@@@@@\033[0;90mC@@O\033[32m@@\033[0;90mO@@@@@@\033[32m@@\033[0;90m@@@@@@@  \033[93mo8OOOOOOOOOOOOOOOO\033[0m8@@@@@@@@@@@@ O@@@@@@@@@@@C @@@@@@@@@@@@@@@@@ o@@@@ c@@@@@@@\033[93mOOOOOOOOOOOOOOOOOOOOOOOOOOOO  \033[90mc@\n");
printf("\033[90m@@@@@@@o\033[32m@@\033[0;90m@@@@\033[32m@@\033[0;90mc@@o\033[32m@@\033[0;90m@8@@@@c\033[32m@@\033[0;90m@@@@@@o  \033[31mCCCC\033[93mOOOOOOOOOOOOO\033[0m@@@@@@@@@@@@@@ O@@@@@@@@@@@C @@@@@@@@@@@@@@@@@c @@@@@@ C@@@@@@\033[93m8OOOOOOOOOOOOOOOOOOOOOOO\033[31mCCCc  \033[90m@\n");
printf("\033[90m@@@@@@@C\033[32m@@\033[0;90moc\033[32m@@@@\033[0;90m@@@@@@o\033[32m@@\033[0;90mo@@o\033[32m@@\033[0;90mO@@@@@  \033[31mcCCCCCCCC\033[93mOOOOOOOO\033[0m@@@@@@@@@@@@@@@  8@@@@@@@@@@@ C@@@@@@@@@@@@@@@@ o@@@@@@@C @@@@@@@\033[93mOOOOOOOOOOOOOOOOOO\033[31mCCCCCCCC  \033[90mo\n");
printf("\033[90m@@@@@@@O\033[32m@@\033[0;90mccoC\033[32m@@\033[0;90m@@@@@@@@\033[32m@@\033[0;90m@@C\033[32m@@\033[0;90mC@@@@8  \033[31moCCCCCCCCCC\033[93mOOOOO\033[0m@@@@@@@@@@@@@@@@@o C@8@@@@@@@@C O@@@@@@@@@@@@@@  8@@@@@@@@@ O@@@@@@\033[93mOOOOOOOOOO\033[31mCCCCCCCCCCCCCCCc  \n");
printf("\033[90m@@@@@@@O\033[32m@@\033[0;90mO@@@\033[32m@@\033[0;90m@@@@@@@@@@@@O\033[32m@@\033[0;90mC@@@@C  \033[31moCCCCCCCCCC\033[93mOOOO\033[0m@@@@@@@@@@@@@@@@@@@@o  oO8@@@8OC\033[95m   \033[0mC@88888888@o  @@@@@@@@@@@@ O@@@@@\033[93m8OOOOOO\033[31mCCCCCCCCCCCCCCCCCCc  \n");
printf("\033[90m@@@@@@@8\033[32m@@@@@@@@@\033[0;90m@@@@@@@8\033[32m@@@@@@\033[0;90mO@@@@o  \033[31mCoCCCCCCCC\033[93mOOOO\033[0m8@@@@@@@@@@@@@@@@@@@@@@@@Oocc\033[95m coCOOOo  \033[0m  cc    8@@@@@@@@@@@@@@@ O@@@@@\033[93m8OOO\033[31mCCCCCCCCCCCCCCCCCCCCo  \n");
printf("\033[90m@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@o  \033[31moCCCCCCC\033[93mOOOOOO\033[0m8@@@@@@@@@@@@@@@@@@@@@@@@@@@@8\033[95m O8OOO8O  \033[0m@@@@@@@@@@@@@@@@@@@@@@@@ O@@@@\033[93m8OOOO\033[31mCCCCCCCCCCCCCCCCCCCo  \n");
printf("\033[90m@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@C  \033[31mCCC\033[93mOOOOOOOOOOO\033[0m8@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@O\033[95m     \033[0mo@@@@@@@@@@@@@@@@@@@@@@@@@@O @@@@\033[93m8OOOO\033[31mCCCCCCCCCCCCCCCCCCoC  \n");
printf("\033[90m@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@O  \033[31mCCC\033[93mOOOOOOOOOOO\033[0m8@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@ C@@@\033[93m8OOOOOOO\033[31mCCCCCCCCCCCCCCoCc  \n");
printf("\033[90m@@@@@@@@@@@@@@@@@@@@@@@\033[91m@@OO\033[90m@@@@@@@@@@  \033[31mcOOC\033[93mOOOOOOOOOO\033[0m8@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@O@@@\033[93m8OOOOOOOOOOOOOOOOOOOO\033[31mCOOc  \n");
printf("\033[90m@@@@@@@@@@@@@\033[91m@OO8@\033[90m@@@\033[91mOccooooo\033[90mC@@@@@@@C  \033[31mooCCCCCCCC\033[93mOOOO\033[0m@@@@@@@@@@@@@@@@@@@@@O o@@@@@@@@@@@@@@@@@@@@o @@@@@@@@@@@@@@@@@@@@@@\033[93m8OOOOOOOOOOOOOOOOOOOO\033[31mCCOO  \033[90mO\n");
printf("\033[90m@@@@@@@@@@@\033[91mCcooooocOoooooOOCoo\033[90mC@@@@@@@  \033[31mcCoCCCCCCCO8C\033[93mc\033[0m       o@@@@@@@@@@@@@@8@o  O@@@@@@@@@@Oo  cO@@@@@@@@@@@@@@@@@@@@@@@@\033[93mOOOOOOOOOOOOOOOOOOOO\033[31mCCCCc  \033[90m@\n");
printf("\033[90m@@@@@@@@@@\033[91mCooooooooooooooCOOoc\033[90mC@@@@@@@O  \033[31mcCCoCCCCC\033[93m   \033[0mc8@@@@@o\033[0m       c8@@@@@@@@@88@@oc    cCO@@88@@@@@@@@@@@@@@@@@@@@@@@@@\033[93mOOOOO\033[31mCCCCCCCCCCCCCCCCCoCo  \033[90mC@\n");
printf("\033[90m@@@@@@@@@@\033[91mOcoooooooooooooCOCoc\033[90m8@@@@@@@@C  \033[31mcCCoCOC \033[0mo@@@\033[95mOOOOO8\033[0m@@O  @@@o\033[0m   @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\033[93mOOOOO\033[31mCCCCCCCCCCCCCCCCCCoO   \033[90m@@\n");
printf("\033[90m@@@@@@@@@@@\033[91mCoooooooooooooOooc\033[90mO@@@@@@@@@@o  \033[31mco\033[0m      \033[0m@@@\033[95m8OOOO8\033[0m@@@@@\033[95m8OOO\033[0m8O\033[0m  O@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\033[93m8OOOOOO\033[31mCCCCCCCCCCCCCCCCCoC   \033[90m@@@\n");
printf("\033[90m@@@@@@@@@@@@\033[91mOcoooooooooooooc\033[90m@@@@@@@@@@@@@O    \033[0mC@@@8@@@@@@@@@@@@@@\033[95mOOOOO\033[0m@@\033[0m  O@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\033[93m8OOOOOOOOO\033[31mCCCCCCCCCCCCoCCoC   \033[90m8@@@\n");
printf("\033[90m@@@@@@@@@@@@@@\033[91mCcoooooooooo\033[90m@@@@@@@@@@@@@8    \033[0mo@\033[95mOOOO\033[0m@@@@@@@@@@@@@@@@\033[95m@8@\033[0m@@@C\033[0m  @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\033[93mOOOOOOOOOOOOO\033[31mCCCCCCCCCCoCooC   \033[90m@@@@@\n");
printf("\033[90m@@@@@@@@@@@@@@@@@\033[91mOocccc8\033[90m@@@@@@@@@@@@@O  \033[93mCc  \033[0m@@\033[95mOOOO\033[0m@@@@\033[95mOOOOOOOOOO8\033[0m@@@@@@@8\033[0m  8@@@@@@@@@@@@@@@@O     \033[36mcc    \033[93mc8@@@@8OOOOOOOOOOOOOOOOOOOOO\033[31mCoCCoCoCc  \033[90mc@@@@@@\n");
printf("\033[90m@@@@@@@@@@@@@@@@@@@@@\033[91m@@\033[90m@@@@@@@@@@@@@  \033[93mC8O  \033[0mc@@@@@@@\033[95m8OOOOOOOOOOOOOO8\033[0m@@@@@8\033[0m  8@@@@@@@@@@@@@@   \033[36m8@@@@@@@@@@O  \033[93mcOOOOOOOOOOOOOOOOOOOOOO\033[31mCCCCOCOOC   \033[90m8@@@@@@@\n");
printf("\033[90m@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@  \033[93m8OOO  \033[0mc@@@@@@\033[95m8OOOOOOOOOOOOOOOO\033[0m@@@@@o\033[0m  @@@@@@@@@@@@@O  \033[94m@8O@O88@O@O\033[36m@@@@@  \033[93mc8OOOOOOOOOOOOOOOO\033[31mCCCOCCOOOc   \033[90mC@@@@@@@@@\n");
printf("\033[90m@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@  \033[93mOOOO8c  \033[0m88@@@@@\033[95mOOOOOOOOOOOOOOO\033[0m@@@@@O\033[0m  O@@@@@@@@@@@@@  \033[94m@O@888@8O@8O@88\033[36m@@@C \033[93mc8OOOOOOOOOOOO\033[31mCCCCCCCOOo    \033[90m@@@@@@@@@@@@\n");
printf("\033[90m@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@O \033[93mc8OOOO8   \033[0m8@@@@@@\033[95m8OOOOOOOOOOO\033[0m@@@@@@O\033[0m   @@@@@@@@@@@@@o \033[94mO8@@8@@@8@OO@@O@8\033[36m@@@c \033[93moOOOOOOOO\033[31mCCCOCCOOOC     \033[90mO@@@@@@@@@@@@@@\n");
printf("\033[90m@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@C \033[93moOOOOOO8c  \033[0mO@8@@@@@@@@@@@@@@@@@@8@\033[0m     OO@@@@@@@@@@@  \033[94mO8@O88@O88@8@O@@O8\033[36m@@@ \033[93mc8\033[31mCCCCCCCOCOOCc      \033[93mc   \033[90m@@@@@@@@@@@@@@\n");
printf("\033[90m@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@  \033[93mCocCCOO oo   \033[0mC888@@@@@@@@@8@c \033[0m   cOo  o88@@@@@@@@@@8 \033[94mcO88O@@@@8O@8@OOOO\033[36m@@@ \033[31m c           \033[31mcccccccccoo   \033[90m@@@@@@@@@@@@\n");
printf("\033[90m@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@  \033[93mc CCOo ooCOCc88888888888888888o cOc  \033[0mcOO@@@@@@@@@@@o \033[94mCOCCOCC8OOC\033[0m      \033[47mc\033[0m   \033[91mccCc \033[31mccccccccccccoooooooo   \033[90mO@@@@@@@@@@\n");
printf("\033[90m@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@O  \033[93moCOo cCoCCOCCCOOOOOOOOOCCCCO  oO  \033[0m   O@88@@@@@@@@@  \033[94moOOOCCOo \033[0;47mC8@@@@@@@@\033[0m \033[91mCOo \033[31mccoocooooooooooooooooo   \033[90m@@@@@@@@@@\n");
printf("\033[90m@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@C \033[93mocCC coCCoCCCCOCCCCCCOCOCCOo  OC c o8c\033[0m  O@88@@@@@@@O  \033[94mCOOo \033[0;47mo8@@@Cc\033[0m      \033[91m O \033[31mcooooooooocooooooooooooo   \033[90m8@@@@@@@@\n");
printf("\033[90m@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@O \033[93mc o8  CoCoCoCCCOCOOCOCCCCCo  oCo o o8O8Oc\033[0m  8@8@@@8@O \033[93m c  \033[0;47mCOOOc\033[0m   \033[100;90mccccCCo\033[0m \033[91mc \033[31moooooooooo \033[31mccooc \033[31mcooooooc   \033[90m@@@@@@@@\n");
printf("\033[90m@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@8 \033[93mccc8c oOooCCCCCooCCoCooCCC  cCCc o COOOOO8C\033[0m  o@@8  \033[93mc8OOOO\033[0m  \033[47mO\033[0m  \033[100;90mccccccccoCc\033[0m \033[31mcooooooooooc \033[31mccc  \033[31mcooooococ  \033[90mc@@@@@@@\n");
printf("\033[90m@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@  \033[93mo 8C   cOCoCCCoCCCoCCCCo   OCC  C OOOOOOOOO8c   O8OOOOOO8C\033[0m  \033[100;90mc\033[0m \033[100;90mc\033[0m \033[100;90mcccc ooC\033[0m  \033[31moooooooooooc \033[31mc  \033[31mccooooooooc  \033[90mO@@@@@@\n");
printf("\033[90m@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@  \033[93mC O8c     OOOOCCCCCCCc   CCCCc Cc OCOOOOOOC  o8OOOOOOOOCCCo\033[0m \033[100;90mc\033[0m \033[100;90mccccccc oCo\033[0m    \033[31mooooooooo    \033[31mcoooooooooc   \033[90m@@@@@@\n");
printf("\033[90m@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@c \033[93mC c8Oc Co              CCCCCC c8  cCCCOOo  OOOOOOOOOCCCC  o8\033[0m  \033[100;90mc\033[0m     \033[100;90mcccooo\033[0m    \033[31mooooooooc  \033[31mccooooooooooc  \033[90mO@@@@@\n");
printf("\033[0m \n");
printf("****************Sorry,Don'be sad**************.\n");
	}
	else
	{
		printf("\n");
printf("\033[0;40;97mO\033[0;40;97mOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO\033[0;40;37mO\033[0;40;37mP\033[0;40;90mC\033[0;40;90m1\033[0;40;90mo\033[0;40;90mC\033[0;40;90mp\033[0;40;37mP\033[0;40;37mP\033[0;40;37mO\033[0;40;97mO\033[0;40;97mOOOOOOOOOOOOOOOOOOOOOOOOOOOO\n");
printf("\033[0;40;97mOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO\033[0;40;37mP \033[0;40;90m-\033[0;40;31mP\033[0;40;91mP\033[0;40;91mPPPP\033[0;40;31mP\033[0;40;90mo\033[0;40;90m+\033[0;40;90mP\033[0;40;37mO\033[0;40;97mO\033[0;40;97mOOOOOOOOOOOOOOOOOOOOOOOOO\n");
printf("\033[0;40;97mOOOOOOOOOOOOOOOOOOOOOOOOO\033[0;40;97mO\033[0;40;97mO\033[0;40;37mOO\033[0;40;97mO\033[0;40;37mO\033[0;40;90m-\033[0;40;90m-\033[0;40;31m0\033[0;40;91mP\033[0;40;91mPPPPPPPP\033[0;40;90mo\033[0;40;90m+\033[0;40;37mP\033[0;40;97mO\033[0;40;97mO\033[0;40;97mOOOOOOOOOOOOOOOOOOOOOO\n");
printf("\033[0;40;97mOOOOOOOOOOOOOOOOOOOO\033[0;40;97mO\033[0;40;37mO\033[0;40;90m0\033[0;40;90mo\033[0;40;90mo\033[0;40;90mP\033[0;40;31mP\033[0;40;31mPPP\033[0;40;90mP\033[0;40;90mo\033[0;40;90m+\033[0;40;90m-c\033[0;40;31mP\033[0;40;91mP\033[0;40;91mPPPPPPPP\033[0;40;31mP\033[0;40;90m1\033[0;40;37mO\033[0;40;97mO\033[0;40;97mO\033[0;40;97mOOOOOOOOOOOOOOOOOOOO\n");
printf("\033[0;40;97mOOOOOOOOOOOOOOOOOOOO\033[0;40;90mc \033[0;40;31mP\033[0;40;91mP\033[0;40;91mPPPPPPPPPP\033[0;40;31mP\033[0;40;90mo\033[0;40;90mc\033[0;40;90mc\033[0;40;90mP\033[0;40;31m0\033[0;40;91mP\033[0;40;91mPPPPPP\033[0;40;31mP\033[0;40;90m+\033[0;40;37mO\033[0;40;97mO\033[0;40;97mOOOOOOOOOOOOOOOOOOO\n");
printf("\033[0;40;97mOOOOOOOOOOOOOOOOOOOO\033[0;40;37mp\033[0;40;90mo\033[0;40;90m1\033[0;40;90mC\033[0;40;31mP\033[0;40;31mP\033[0;40;31mP\033[0;40;31mP\033[0;40;31mP\033[0;40;31mPPPPPP\033[0;40;91mPPP\033[0;40;31mP\033[0;40;31mP\033[0;40;31mo\033[0;40;31mp\033[0;40;31mO\033[0;40;31mP\033[0;40;91mP\033[0;40;91mPPP\033[0;40;31mP\033[0;40;90mc\033[0;40;37mO\033[0;40;97mO\033[0;40;97mOOOOOOOOOOOOOOOOOO\n");
printf("\033[0;40;97mOOOOOOOOOOOOOOOOOOOOOOO\033[0;40;97mO\033[0;40;37mO\033[0;40;90mC  \033[0;40;90mc\033[0;40;90mo\033[0;40;31mP\033[0;40;31mP\033[0;40;31mP\033[0;40;31mP\033[0;40;91mP\033[0;40;91mPPPPPPPPPPPPPPP\033[0;40;90m-\033[0;40;90mc\033[0;40;37mO\033[0;40;37mO\033[0;40;97mO\033[0;40;97mO\033[0;40;97mOOOOOOOOOOOOOO         ~ ~ ~ ~ ~ ~ Congratulations,have a nice summer vacation! ~ ~ ~ ~ ~ ~\n");
printf("\033[0;40;97mOOOOOOOOOOOOOOOOOOOOO\033[0;40;97mO\033[0;40;37mP\033[0;40;90mc\033[0;40;90m-\033[0;40;90mo\033[0;40;31mP\033[0;40;91mP\033[0;40;91mPPPPPPPPPPPPPPPPPPPPPPPP\033[0;40;31mP\033[0;40;90m+\033[0;40;90m-\033[0;40;90mC\033[0;40;37mO\033[0;40;97mO\033[0;40;97mO\033[0;40;97mOOOOOOOOOOO    \n");
printf("\033[0;40;97mOOOOOOOOOOOOOOOOOOO\033[0;40;37mO\033[0;40;37mP \033[0;40;90mc\033[0;40;31mP\033[0;40;91mP\033[0;40;91mPPPPPPPPPPPPPPPPPPPPPPPPPPPPPP\033[0;40;31mP\033[0;40;90m+\033[0;40;90m-\033[0;40;90mO\033[0;40;37mO\033[0;40;97mO\033[0;40;97mOOOOOOOOO\n");
printf("\033[0;40;97mOOOOOOOOOOOOOOOOO\033[0;40;97mO\033[0;40;37mP \033[0;40;90mo\033[0;40;31mP\033[0;40;91mP\033[0;40;91mPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPP\033[0;40;31mP\033[0;40;90m-\033[0;40;90mo\033[0;40;37mO\033[0;40;97mO\033[0;40;97mOOOOOOO\n");
printf("\033[0;40;97mOOOOOOOOOOOOOOOO\033[0;40;37mP\033[0;40;90m-\033[0;40;90m+\033[0;40;31mP\033[0;40;91mP\033[0;40;91mPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPP\033[0;40;31mP\033[0;40;90m-\033[0;40;90mC\033[0;40;37mO\033[0;40;97mO\033[0;40;97mOOOOO\n");
printf("\033[0;40;97mOOOOOOOOOOOOOO\033[0;40;37mP\033[0;40;90mC\033[0;40;90m-\033[0;40;31mP\033[0;40;91mP\033[0;40;91mPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPP\033[0;40;31mP\033[0;40;90m-\033[0;40;37mO\033[0;40;97mO\033[0;40;97mO\033[0;40;97mOOO\n");
printf("\033[0;40;97mOOOOOOOO\033[0;40;97mOOOOO\033[0;40;37mP\033[0;40;90m-\033[0;40;90m+\033[0;40;91mP\033[0;40;91mPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPP\033[0;40;90mc\033[0;40;90mo\033[0;40;97mO\033[0;40;97mO\033[0;40;97mOO\n");
printf("\033[0;40;97mOOOOO\033[0;40;97mO\033[0;40;37mP\033[0;40;90mo\033[0;40;90m-\033[0;40;37mO\033[0;40;97mO\033[0;40;97mO\033[0;40;37mP \033[0;40;31mP\033[0;40;91mP\033[0;40;91mPPPPPPPPPPPPPPPPPPPP\033[0;40;90mC\033[0;40;90mC\033[0;40;31mP\033[0;40;31mP\033[0;40;91mP\033[0;40;91mPPPPPPPPPPPPPPPPPPPPPPPP\033[0;40;90m+\033[0;40;90m-\033[0;40;97mO\033[0;40;97mO\033[0;40;97mO\n");
printf("\033[0;40;97mO\033[0;40;37mP\033[0;40;37mP\033[0;40;37mO\033[0;40;97mO\033[0;40;37mp\033[0;40;90mc\033[0;40;90m-\033[0;40;90m--\033[0;40;37mO\033[0;40;37mP \033[0;40;31mP\033[0;40;91mP\033[0;40;91mPPPPPPPPPPPPPPPPPPPP\033[0;40;31mP     \033[0;40;90m-\033[0;40;90m-\033[0;40;90m1\033[0;40;90mC\033[0;40;31mP\033[0;40;31mP\033[0;40;91mP\033[0;40;91mPPPPPPPPPPP\033[0;40;31mP\033[0;40;31mP\033[0;40;90mC\033[0;40;90mc\033[0;40;90m-\033[0;40;90m-  \033[0;40;90mc\033[0;40;97mO\033[0;40;97mO\n");
printf("\033[0;40;37mP\033[0;40;90m-\033[0;40;90m-\033[0;40;90m-\033[0;40;90m-\033[0;40;90mC\033[0;40;37mP\033[0;40;37mO\033[0;40;90m+\033[0;40;90m-\033[0;40;90m--\033[0;40;90mo\033[0;40;91mP\033[0;40;91mPPPPPPPPPPPPPPPPPPPPP\033[0;40;90mo\033[0;40;90m-           \033[0;40;90m-\033[0;40;90mc\033[0;40;90mC\033[0;40;31mP\033[0;40;31mP\033[0;40;31mP\033[0;40;90mC\033[0;40;90mc\033[0;40;90m-           \033[0;40;37mO\033[0;40;97mO\n");
printf("\033[0;40;90mp\033[0;40;90m-\033[0;40;90m-\033[0;40;90m-\033[0;40;90m-----\033[0;40;90m- \033[0;40;90m-\033[0;40;91mP\033[0;40;91mPPPPPPPPPPPPPPPPPPPPPPPPP\033[0;40;31mP\033[0;40;90mC\033[0;40;37mp\033[0;40;37mp\033[0;40;37mp\033[0;40;37mp\033[0;40;90mp\033[0;40;90m1\033[0;40;90m-            \033[0;40;90m-\033[0;40;90m1\033[0;40;90mp\033[0;40;90m-\033[0;40;90m+\033[0;40;90mo\033[0;40;31mP\033[0;40;31mP\033[0;40;31mP \033[0;40;37mO\n");
printf("\033[0;40;97mO\033[0;40;97mO\033[0;40;97mO\033[0;40;97mO\033[0;40;37mO\033[0;40;37mO\033[0;40;37mO\033[0;40;90mP\033[0;40;90m1\033[0;40;90m- \033[0;40;31m0\033[0;40;91mP\033[0;40;91mPPPPPPPPPPPPPPPPP\033[0;40;31mPPPPPPP\033[0;40;31mP\033[0;40;31mP\033[0;40;37mO\033[0;40;97mO\033[0;40;97mOOOO\033[0;40;97mO\033[0;40;37mP\033[0;40;90mC\033[0;40;90mP\033[0;40;37mO\033[0;40;37mO\033[0;40;37mP\033[0;40;90mc\033[0;40;37mO\033[0;40;37mP\033[0;40;37mP\033[0;40;37mO\033[0;40;97mO\033[0;40;97mO\033[0;40;97mOOO\033[0;40;97mO\033[0;40;90m+\033[0;40;31mP\033[0;40;91mP\033[0;40;91mPP\033[0;40;90m-\033[0;40;37mO\n");
printf("\033[0;40;97mO\033[0;40;97mOOO\033[0;40;37mp \033[0;40;90m-\033[0;40;90m-\033[0;40;37mp\033[0;40;37mP \033[0;40;31mP\033[0;40;91mPPPPPPPPPPPPPPPP\033[0;40;31mP\033[0;40;31mP\033[0;40;31mPP\033[0;40;31mP\033[0;40;91mP\033[0;40;91mPP\033[0;40;31mP\033[0;40;31mP\033[0;40;90mo\033[0;40;37mO\033[0;40;97mO\033[0;40;97mO\033[0;40;97mOOO\033[0;40;37mO   \033[0;40;37mp\033[0;40;97mO\033[0;40;37mP\033[0;40;90m0\033[0;40;97mO\033[0;40;90m1 \033[0;40;90m-\033[0;40;37mO\033[0;40;97mO\033[0;40;97mOOO\033[0;40;97mO\033[0;40;90mP\033[0;40;31mP\033[0;40;31mP\033[0;40;91mP\033[0;40;91mP\033[0;40;90m-\033[0;40;90mC\n");
printf("\033[0;40;97mO\033[0;40;97mOOOO\033[0;40;37mp\033[0;40;37mO\033[0;40;97mO\033[0;40;97mO\033[0;40;37mP \033[0;40;91mP\033[0;40;91mPPPPPPPPPPPPPPPP\033[0;40;31mP\033[0;40;31mPPPP\033[0;40;91mP\033[0;40;91mP\033[0;40;31mP\033[0;40;31mP\033[0;40;31mPP\033[0;40;90m-\033[0;40;37mO\033[0;40;97mO\033[0;40;97mO\033[0;40;97mO\033[0;40;97mOO\033[0;40;97mO\033[0;40;37mO\033[0;40;37mO\033[0;40;37mP\033[0;40;90mp\033[0;40;90mp\033[0;40;90mp\033[0;40;90mp\033[0;40;90m0\033[0;40;37mP\033[0;40;37mO\033[0;40;97mO\033[0;40;97mOO\033[0;40;97mO\033[0;40;97mO\033[0;40;37mP\033[0;40;90mc\033[0;40;31mP\033[0;40;31mP\033[0;40;91mP\033[0;40;91mP\033[0;40;90m-\033[0;40;90mo\n");
printf("\033[0;40;97mO\033[0;40;97mOOOOOOOO\033[0;40;37mP \033[0;40;91mP\033[0;40;91mPPPPPPPPP\033[0;40;31mP\033[0;40;31mPP\033[0;40;31mP\033[0;40;91mP\033[0;40;91mP\033[0;40;31mP\033[0;40;31mP\033[0;40;31mPPPP\033[0;40;31mP\033[0;40;91mP\033[0;40;31mP\033[0;40;31mP\033[0;40;31mPPP\033[0;40;90mc\033[0;40;90m-\033[0;40;90mP\033[0;40;37mP\033[0;40;37mP\033[0;40;37mP\033[0;40;37mO\033[0;40;33mp\033[0;40;33mO\033[0;40;33mO\033[0;40;33mOOOOO\033[0;40;33mO\033[0;40;33mO\033[0;40;90mp\033[0;40;37mP\033[0;40;37mP\033[0;40;90m0\033[0;40;90m+\033[0;40;90mo\033[0;40;31mP\033[0;40;31mPP\033[0;40;91mP\033[0;40;91mP \033[0;40;37mO\n");
printf("\033[0;40;97mO\033[0;40;97mOOOOOOOO\033[0;40;37mp \033[0;40;31m0\033[0;40;91mP\033[0;40;91mPPPPPPP\033[0;40;31mP\033[0;40;31mP\033[0;40;31mPPP\033[0;40;31mP\033[0;40;91mP\033[0;40;91mP\033[0;40;31mP\033[0;40;31mPPPP\033[0;40;91mP\033[0;40;91mPP\033[0;40;31mP\033[0;40;31mPPPPP\033[0;40;31mP\033[0;40;90mc\033[0;40;90mo\033[0;40;33mO\033[0;40;33mO\033[0;40;33mOOOOOOOOOOOO\033[0;40;33mO\033[0;40;90mp\033[0;40;31mP\033[0;40;31mP\033[0;40;31mP\033[0;40;31mP\033[0;40;91mP\033[0;40;91mP\033[0;40;90mP \033[0;40;37mO\n");
printf("\033[0;40;97mO\033[0;40;97mOOOOOOOO\033[0;40;97mO\033[0;40;90m-\033[0;40;90m-\033[0;40;91mP\033[0;40;91mPPPPPPPP\033[0;40;31mP\033[0;40;31mP\033[0;40;31mPP\033[0;40;31mP\033[0;40;91mPPP\033[0;40;31mP\033[0;40;31mPP\033[0;40;91mP\033[0;40;91mP\033[0;40;91mP\033[0;40;91mP\033[0;40;91mP\033[0;40;90mp\033[0;40;90mp\033[0;40;90mpp\033[0;40;90mP\033[0;40;90m-\033[0;40;33mO\033[0;40;33mO\033[0;40;33mOOOOOOOOOOOOOOOO\033[0;40;33mO\033[0;40;90mp\033[0;40;31m0\033[0;40;91mP\033[0;40;91mP\033[0;40;31mP \033[0;40;90m0\033[0;40;97mO\n");
printf("\033[0;40;97mOOOOOOOOOO\033[0;40;37mO \033[0;40;90mc\033[0;40;91mP\033[0;40;91mPPPPPPPPPPPPPP\033[0;40;91mO\033[0;40;90mp\033[0;40;90m0\033[0;40;90mO\033[0;40;37mO\033[0;40;37mO\033[0;40;37mO\033[0;40;37mOOOOOO\033[0;40;37mO\033[0;40;90mp\033[0;40;90m-\033[0;40;33mO\033[0;40;33m0\033[0;40;33mP\033[0;40;33mPP\033[0;40;33mO\033[0;40;33mO\033[0;40;33mO\033[0;40;33mO\033[0;40;33mO\033[0;40;33mO\033[0;40;33mO\033[0;40;33mOOOOOOO\033[0;40;90mP\033[0;40;31mP\033[0;40;91mP\033[0;40;90m-\033[0;40;90m-\033[0;40;97mO\033[0;40;97mO\n");
printf("\033[0;40;97mOOOOOOOOOOO\033[0;40;37mO \033[0;40;90m-\033[0;40;31m0\033[0;40;91mP\033[0;40;91mPPPPPPPP\033[0;40;91mO\033[0;40;90mp\033[0;40;37mO\033[0;40;37mO\033[0;40;37mO\033[0;40;37mOOOOOOOOOOOOOO\033[0;40;37mO\033[0;40;90mC\033[0;40;90mP\033[0;40;33mO\033[0;40;33mPPOO\033[0;40;33mO\033[0;40;33mO\033[0;40;33mO\033[0;40;33mO\033[0;40;33mO\033[0;40;33mO\033[0;40;33mO\033[0;40;33mO\033[0;40;90m1\033[0;40;90mo\033[0;40;31mP\033[0;40;90mp\033[0;40;90mo\033[0;40;90mc\033[0;40;90m-\033[0;40;90m-\033[0;40;37mO\033[0;40;97mO\033[0;40;97mO\n");
printf("\033[0;40;97mOOOOOOOOOOOO\033[0;40;37mO\033[0;40;90mC \033[0;40;90mc\033[0;40;31mP\033[0;40;91mP\033[0;40;91mPPP\033[0;40;91mO\033[0;40;90mp\033[0;40;37mO\033[0;40;37mO\033[0;40;37mOOOOOOOOOOOOOOOOOOOO\033[0;40;37mO\033[0;40;90mo\033[0;40;90mP\033[0;40;33mO\033[0;40;33mP\033[0;40;33mPPPPP\033[0;40;33mP\033[0;40;33mP\033[0;40;90mp\033[0;40;31mP\033[0;40;91mP\033[0;40;91mPPP\033[0;40;90mC \033[0;40;90mo\033[0;40;37mO\033[0;40;97mO\033[0;40;97mOO\n");
printf("\033[0;40;97mOOOOOOOOOOOOOO\033[0;40;37mO\033[0;40;90mo \033[0;40;90m-\033[0;40;90mC\033[0;40;31m0\033[0;40;90mO\033[0;40;37mO\033[0;40;37mOOOOOOOOOOOOOOOOOOOOOOOOO\033[0;40;37mO\033[0;40;90mo\033[0;40;90mC\033[0;40;33mO\033[0;40;33mOP\033[0;40;90mP\033[0;40;90mp\033[0;40;90mp\033[0;40;37mO\033[0;40;37mO\033[0;40;91mP\033[0;40;91mP\033[0;40;31mP\033[0;40;90mC \033[0;40;90m-\033[0;40;37mp\033[0;40;97mO\033[0;40;97mOOOO\n");
printf("\033[0;40;97mOOOOOOOOOOOOOOOO\033[0;40;37mO\033[0;40;37mp\033[0;40;90m1 \033[0;40;90mc\033[0;40;90mP\033[0;40;37mO\033[0;40;37mO\033[0;40;37mO\033[0;40;37mOOOOOOOOOOOOOOOOOOOOOOOO\033[0;40;37mO\033[0;40;90mp\033[0;40;90m+\033[0;40;37mO\033[0;40;37mO\033[0;40;37mO\033[0;40;37mOO\033[0;40;37mO\033[0;40;90mP\033[0;40;90m- \033[0;40;90mo\033[0;40;37mp\033[0;40;97mO\033[0;40;97mO\033[0;40;97mOOOOO\n");
printf("\033[0;40;97mOOOOOOOOOOOOOOOOOOO\033[0;40;37mO\033[0;40;37mp\033[0;40;90mp\033[0;40;90m- \033[0;40;90m-\033[0;40;90mC\033[0;40;90mP\033[0;40;37mO\033[0;40;37mO\033[0;40;37mO\033[0;40;37mO\033[0;40;37mOOOOOOOOOOOOOOOOOOOOO\033[0;40;37mO\033[0;40;37mP\033[0;40;90mP\033[0;40;90mC\033[0;40;90m- \033[0;40;90mo\033[0;40;37mp\033[0;40;37mO\033[0;40;97mO\033[0;40;97mOOOOOOOO\n");
printf("\033[0;40;97mOOOOOOOOOOOOOOOOOOOOOOO\033[0;40;97mO\033[0;40;37mO\033[0;40;37mp\033[0;40;90mp\033[0;40;90m1\033[0;40;90m- \033[0;40;90m-\033[0;40;90m-\033[0;40;90m+\033[0;40;90mC\033[0;40;90mP\033[0;40;90mP\033[0;40;90mP\033[0;40;37mP\033[0;40;37mP\033[0;40;37mP\033[0;40;37mOOPP\033[0;40;37mP\033[0;40;90mP\033[0;40;90mP\033[0;40;90m0\033[0;40;90mC\033[0;40;90m1\033[0;40;90m- \033[0;40;90m-\033[0;40;90m+\033[0;40;37mp\033[0;40;37mp\033[0;40;37mO\033[0;40;97mO\033[0;40;97mO\033[0;40;97mOOOOOOOOOOO\n");
printf("\033[0;40;97mOOOOOOOOOOOOOOOOOOOOOOOOOOOOO\033[0;40;97mO\033[0;40;37mO\033[0;40;37mO\033[0;40;37mO\033[0;40;37mp\033[0;40;37mp\033[0;40;37mp\033[0;40;37mp\033[0;40;90mp\033[0;40;90mp\033[0;40;90mp++pp\033[0;40;90mp\033[0;40;37mp\033[0;40;37mp\033[0;40;37mp\033[0;40;37mp\033[0;40;37mO\033[0;40;37mO\033[0;40;97mO\033[0;40;97mO\033[0;40;97mOOOOOOOOOOOOOOOOO\n");
printf("\033[0;40;90m                                                                      \n");
printf("\033[0;40;90m                                                                      \n");
printf("\033[0;40;90m                                                                      \n");
printf("\033[0;40;90m                                                                      \n");
printf("\n");
printf("\n");
printf("\033[0m \n");
	}
		

	return 0;
}
