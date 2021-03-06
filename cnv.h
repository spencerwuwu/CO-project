#include <stdio.h>
#include <stdlib.h>
#define kernSize 5
#define numInput 2
#define numFilter 2

extern BYTE *data[numInput];
extern BYTE *results[numFilter][numInput];

extern int imgHeight, imgWidth, imgSize;

int filters[numFilter][kernSize][kernSize] = {
  	 1,  0,  0,  0,  0,             //
	 0,  1,  0,  0,  0,             //
	 0,  0,  1,  0,  0,             //Blur kernel
	 0,  0,  0,  1,  0,             //
	 0,  0,  0,  0,  1,             //

     0,     0,    -1,   0,    0,     //
     0,    -1,    -2,  -1,    0,     //
    -1,    -2,    16,  -2,   -1,     //Laplace of gaussian kernel
     0,    -1,    -2,  -1,    0,     //
     0,     0,    -1,   0,    0      //
		 
};

int filter2[kernSize][kernSize] = {
     0,     0,    -1,   0,    0,     //
     0,    -1,    -2,  -1,    0,     //
    -1,    -2,    16,  -2,   -1,     //Laplace of gaussian kernel
     0,    -1,    -2,  -1,    0,     //
     0,     0,    -1,   0,    0      //
};


int weights[numFilter] = {5, 0};


int getIdx(int y, int x)
{
	return y*imgWidth + x;
}

void checkPixelValue(int *arr, int weight)
{
	int i;

	for(i = 0; i < 3; i++){
		if(weight != 0)
			arr[i] = arr[i] / weight;
		if(arr[i] < 0)
			arr[i] = 0;
		else if(arr[i] > 255)
			arr[i] = 255;
	}
}

void setPixel(BYTE *data, int idx, int *rgb)
{
	Pixel *pixelPtr;

	pixelPtr = (Pixel *) &data[idx*sizeof(Pixel)];
	pixelPtr->R = rgb[0]; 
	pixelPtr->G = rgb[1]; 
	pixelPtr->B = rgb[2];
}




void cross2DConv()
{
	int i, j, k, l;
	int filIdx, inIdx;
    int getIdx_result;
	int weight, kernLen;
	int rgb[3], idx[3];
    int tmp;
	Pixel *pixelPtr;

	kernLen = kernSize/2;

	for(i = 0; i < imgWidth; i++){
		for(j = 0; j <= i && j < imgHeight; j++){
            getIdx_result = getIdx(j, i - j);
			for(inIdx = 0; inIdx < numInput; inIdx++){
				for(filIdx = 0; filIdx < numFilter; filIdx++){
					rgb[0] = 0; rgb[1] = 0; rgb[2] = 0;
                    weight = weights[filIdx];
                    for(k = 0; k < kernSize; k++){
                        for(l = 0; l < kernSize; l++){
                            idx[0] = getIdx_result;
                            idx[1] = idx[0]%imgWidth - kernLen + l;
                            idx[2] = idx[0]/imgWidth - kernLen + k;
                            if((idx[1] >= 0) && (idx[2] >= 0) && 
                                    (idx[1] < imgWidth) && (idx[2] < imgHeight)){
                                pixelPtr = (Pixel *) &data[inIdx][getIdx(idx[2], idx[1])* sizeof(Pixel)];
                                if ( filIdx == 0 )
                                {
                                    if ( k == l )
                                    { 
                                        rgb[0] += (pixelPtr->R - 0);
                                        rgb[1] += (pixelPtr->G - 0);
                                        rgb[2] += (pixelPtr->B - 0);
                                    }
                                }
                                else
                                {
                                    rgb[0] += filter2[k][l] * (pixelPtr->R - 0);
                                    rgb[1] += filter2[k][l] * (pixelPtr->G - 0);
                                    rgb[2] += filter2[k][l] * (pixelPtr->B - 0);
                                }

                            }                               
                            else                            
                                weight -= filters[filIdx][k][l];
                        }
                    }		
                    checkPixelValue(rgb, weight);
                    setPixel(results[filIdx][inIdx], idx[0], rgb);
                }
            }
        }
    }
    for(i = 0; i < imgHeight+1; i++){
        for(j = 0; j <= i; j++){
            getIdx_result = getIdx(imgHeight - j, imgWidth - i + j);
            for(inIdx = 0; inIdx < numInput; inIdx++){
                for(filIdx = 0; filIdx < numFilter; filIdx++){
                    rgb[0] = 0; rgb[1] = 0; rgb[2] = 0;
                    weight = weights[filIdx];
                    for(k = 0; k < kernSize; k++){
                        for(l = 0; l < kernSize; l++){
                            idx[0] = getIdx_result;
                            idx[1] = idx[0]%imgWidth - kernLen + l;
                            idx[2] = idx[0]/imgWidth - kernLen + k;
                            if((idx[1] >= 0) && (idx[2] >=0) && 
                                    (idx[1] < imgWidth) && (idx[2] < imgHeight)){
                                pixelPtr = (Pixel *) &data[inIdx][getIdx(idx[2], idx[1])* sizeof(Pixel)];
                                if ( filIdx == 0 )
                                {
                                    if ( l == k ) 
                                    {
                                        rgb[0] += (pixelPtr->R - 0);
                                        rgb[1] += (pixelPtr->G - 0);
                                        rgb[2] += (pixelPtr->B - 0);
                                    }
                                }
                                else
                                {
                                    rgb[0] += filter2[l][k] * (pixelPtr->R - 0);
                                    rgb[1] += filter2[l][k] * (pixelPtr->G - 0);
                                    rgb[2] += filter2[l][k] * (pixelPtr->B - 0);
                                }
                            }                               
                            else                            
                                weight -= filters[filIdx][l][k];
                        }
                    }		
                    checkPixelValue(rgb, weight);
                    setPixel(results[filIdx][inIdx], idx[0], rgb);
                }
            }
        }
    }
}


