#include"AD_BCF_Launcher.h"

void delete_lastChar(char ** input);


//////////////////////////////////////////////////////////////
//Default Constructor
//BloomFilter의 배열을 생성한다.
AD_CBF_Launcher::AD_CBF_Launcher()
{
	//File Open
	if(fopen_s(&traffic_file, "D:\\DH_Simul_Code\\2IP_Dest_Bot.txt", "r"))
	{
		fprintf(stderr, "ERROR: FILE OPen Error! \n");
		return;
	}//if

	//Log File Open
	if (fopen_s(&log_file, "log.txt", "w"))
	{
		fprintf(stderr, "ERROR: FILE OPen Error! \n");
		return;
	}//if


	//Memory Allocate of BloomFilter's Array
	Bloom = new BloomFilter(MAX_MEMORY_SIZE);	
	Bloom_BL = new BloomFilter(MAX_MEMORY_SIZE);
	
	//IP정보를 임시 저장하는 객체 생성
	ip = new IP_Info;
	
	//실험환경 변수(sim_params)설정
	sim_params = NULL;
	b_flag = true;
}//Default Constructor

//////////////////////////////////////////////////////////////
//Destroyer
AD_CBF_Launcher::~AD_CBF_Launcher()
{
	delete ip;
	//File Close
	fclose(traffic_file);
	fclose(log_file);
	delete Bloom;
	delete Bloom_BL;
}//소멸자

///////////////////////////////////////////////////////////////
//initParams
void AD_CBF_Launcher::initParams(unsigned long M, int nfuncs, double dabothre, int countthre)
{
	if (this->sim_params != NULL)
	{
		delete sim_params;
	}
	sim_params = new Simul_Params(M,nfuncs, dabothre, countthre);
}//initParams


//BloomFilter에, 실험환경값을 저장/////////////////////////////
void AD_CBF_Launcher::BloomFilter_Setting()
{
	//sim_params를 이용하여 BloomFilter의 값들을 초기화
	Bloom->setParam( sim_params->getMSize(), sim_params->getCountThreshold(), sim_params->getNFuncs(), SAXHash, RSHash, JSHash, BKDRHash, APHash, FNVHash, SDBMHash, DJBHash);
	Bloom_BL->setParam( sim_params->getMSize(), sim_params->getCountThreshold(), sim_params->getNFuncs(), SAXHash, RSHash, JSHash, BKDRHash, APHash, FNVHash, SDBMHash, DJBHash);
}//


//IP_Select/////////////////////////////////////////////
//로그 파일로부터 1 Line을 읽어들여 여기서 각종 정보를 Parsing후
// ip멤버에 저장.
void AD_CBF_Launcher :: IP_Select()
{
	char * time_tmp;
	char * ip_tmp;
	char * type_tmp;
	char token[2] = "\t";
	double t_tmp;
	int i_tmp;

	//파일에서 1Line을 읽어 들인다.
	fgets(buffer, 256, traffic_file);
	
	//token을 이용해 time, ip, type을 구분한다.
	time_tmp = strtok(buffer, token);
	ip_tmp = strtok(NULL, token);
	type_tmp = strtok(NULL, token);
	
	//IP문자열의 맨마지막에 \0 삽입
	delete_lastChar(&type_tmp);
	
	//ip정보 입력
	ip->setIP(ip_tmp);
	ip->setType(type_tmp);
	
	//time 입력
	t_tmp = strtod(time_tmp, NULL);
	ip->setTime(t_tmp);
	
	//i_time 입력
	i_tmp = (int)(ip->getTime() * 1000); 
	ip->setITime(i_tmp);
	
	//cout << ip->getTime() << "\t" << ip->getITime() << "\t" <<ip->getIP() << "\t" << ip->getType() << endl;

}//IP_Select


////////////////////////////////////////////////////////////////////////////////
//실질적으로 BloomFilter가 DDoS공격을 탐지하고, 이를 방어하는 루틴.
//IP_Select에서 읽어들인 1 Line의 ip를 탐지및방어 루틴에 적용한다.
double AD_CBF_Launcher::Simulation_Start()
{
	unsigned long ip_long;
	char ip_str[IP_BUFFER_SIZE];

	unsigned int botDetectedCnt = 0;				//봇으로 판명난 IP의 갯수
	unsigned int DABO_Cnt = 0;						//DABO가 일어난 횟수
	unsigned int numDetectedBotInOneSec = 0;		
	unsigned int numPktInOneSec = 0;
	unsigned int numpktintoBF = 0; 

	int patternIdx = 0;
	int pattern_switch_cnt = 0;
	int fp_cnt = 0;

	double now_time_cnt=0.0;

	int now_time_int, pre_time_int=0;

	double numOfBot=0;
	double intensity;
	double lastContectedTime = 0.0;
	double samplingRate = 0.0;
	int samplingStep = 257;							//Default Sampling Step
	double measuredIntensity = -1;
	int time_cnt = 0;
	int fp_BL = 0;
	int numPktforDABAO = 0;
	int nminAverage = 999999;
	char buf[100];
	int endSignal = 0;
	bool DaboFlag = false;
	bool startFlag = true;
	bool isMonitor = true;
	FILE * log_pass_file;
	int dabo_mon = 0, dabo_mon_his_0 = 0, dabo_mon_his_1 = 0, dabo_mon_his_2 = 0, dabo_mon_his_3 = 0, dabo_mon_his_4 = 0, dabo_mon_tot = 0;
	int Detection_Threshold = 4;

	fopen_s(&log_pass_file, "log_pass.txt", "w");

	fprintf(log_file, "time\tbotDetectedCnt\tsamplingRate\tmeasuredIntensity\tsamplingStep\tnumDetectedBotInOneSec\tDABO_Cnt\tNum1s()\tNumThres()\tfp_cnt\n");
	
	////////////////////////////////////////////////////////////////////////////
	//1. Monitoring
//	IP_Select(); 
	while (!feof(traffic_file))
	{
		IP_Select();		//Read From Traffic File
		ip_long = inet_addr(ip->getIP());		//IP to long
		sprintf(ip_str, "%X\0", ip_long);		//long to char *
		
		numPktInOneSec++;						//1초에 들어온 IP갯수 증가

		if (isMonitor)
		{
			numPktforDABAO++;						//다보를 일으키기 까지 들어온 Packet 수 증가


			//필터에 IP를 넣고 Threshold값을 넘었는지를 검사한다.
			//넘지 않았다면 필터에 등록하고, 넘었다면 nDabo와 nminAverage를 계산한다
			if (Bloom->bloom_check(ip_str) < Bloom->getMaxCount())
			{
				Bloom->bloom_add(ip_str);
				numpktintoBF++;
			}//if
			else
			{
				//처음으로 Threshold값을 넘겼을 때만 지금까지 들어온 패킷의 반으로 한다
				//나머지는 MovingAverage값으로 nDabo값을 계산한다.
				dabo_mon++;

				if (startFlag)
				{
					nminAverage = numPktforDABAO / 2;
					startFlag = false;
				}//if
				else
				{
					nminAverage = 0.875*nminAverage + 0.125*numPktforDABAO;
				}//else
				//nminAverage=max(20,nminAverage);
			}//else

			//DABO
			if (numPktforDABAO > nminAverage)
			{
				Bloom->bloom_allDecrease();
				nminAverage++;
				numPktforDABAO = 0;
				dabo_mon = 0;
			}//if

			printf("Time = [%d]\tnumPktInOneSec = [%d]\NumpacketforDABO = [%d]\nminAverage = [%d]\tdabo_mon = [%d]\n",
				ip->getITime(), numPktInOneSec, numPktforDABAO, nminAverage,dabo_mon);
			fprintf(log_file, "%d\t%d\t%d\t%d\t%d\n", ip->getITime(), numPktInOneSec, numPktforDABAO, nminAverage, dabo_mon);

			fprintf(log_pass_file, "%f\t%s\t%s\t\n",ip->getTime(), ip->getIP(), ip->getType());

			dabo_mon_his_4 = dabo_mon_his_3;
			dabo_mon_his_3 = dabo_mon_his_2;
			dabo_mon_his_2 = dabo_mon_his_1;
			dabo_mon_his_1 = dabo_mon_his_0;
			dabo_mon_his_0 = dabo_mon;
			
			dabo_mon_tot = dabo_mon_his_0 + dabo_mon_his_1 + dabo_mon_his_2 + dabo_mon_his_3 + dabo_mon_his_4;

			if(dabo_mon_tot > Detection_Threshold)
			{
				isMonitor = false;
			}

			//dabo_mon = 0;
					
			numPktInOneSec = 0;
			numpktintoBF = 0;
		}
		else // bot discovery
		{
			now_time_cnt = ip->getTime();

			if (Bloom_BL->bloom_check(ip_str) > 0)
			{
				// shlee checkpoint
				intensity = (now_time_cnt - lastContectedTime) * (double)(numOfBot);
				lastContectedTime = now_time_cnt;
				if (measuredIntensity < 0)
					measuredIntensity = intensity;
				else if (intensity > 0)
					measuredIntensity = 0.875*measuredIntensity + 0.125*(intensity); 
			
				numPktInOneSec--;
				//continue;					//Packet Drop!
			}//if


			//Sampling Operation
			else if (samplingStep > 0 && checkPattern(ip_long, samplingStep, patternIdx) == 0)
			{
				fprintf(log_pass_file, "%f\t%s\t%s\t\n",ip->getTime(), ip->getIP(), ip->getType());
				//it is not Sampling IP
				//continue;
			}//end of Sampling Operation
	
			//해당 트래픽을 BloomFilter에 넣고 임계점을
			//넘지 않았다면 BloomFilter에 등록
			else if (Bloom->bloom_check(ip_str) < Bloom->getMaxCount())
			{
				Bloom->bloom_add(ip_str);
				numPktforDABAO++;
				numpktintoBF++;

				fprintf(log_pass_file, "%f\t%s\t%s\t\n",ip->getTime(), ip->getIP(), ip->getType());
			}//if
			//해당 트래픽이 임계점(여기선4)를 넘었다면 블랙리스트에 추가
			else
			{
				Bloom_BL->bloom_add(ip_str);
				numOfBot++;
				if (strcmp(ip->getType(), "Normal") == 0)
				{
					numDetectedBotInOneSec++;
					fp_cnt++;
				}//if
				else
				{
					botDetectedCnt++;
					numDetectedBotInOneSec++;
				}//else
				
			}//else
	
			//DABO
			if (numPktforDABAO > nminAverage)
			{
				Bloom->bloom_allDecrease();
				numPktforDABAO = 0;
				DABO_Cnt++;
			}//if of DABO



			now_time_int = ip->getITime();
			if(now_time_int > pre_time_int)
			{
					//Get Sampling Step & Sampling Rate
				if (measuredIntensity >= 0 && numPktInOneSec > 0)
				{
					//해당 시간에 봇을 탐지 못한다면 Threshold/A만큼 기다려야 한다
					if (numDetectedBotInOneSec == 0)
						time_cnt++;
					else
						time_cnt = 0;
					if (measuredIntensity != 0)
					{
						if (time_cnt > (int)(sim_params->getCountThreshold() / measuredIntensity))
						{
							if (b_flag)
							{
								samplingRate = (double)((double)(nminAverage * measuredIntensity) / (double)(numPktInOneSec * 2));
								samplingStep = (int)ceil(1.0 / samplingRate);
	
								patternIdx = 0;
								b_flag = false;
								time_cnt = 0;
								if (samplingStep == 1)
								{
									isMonitor = true;
									b_flag = true;
								}
							}//if
							else
							{
								if(patternIdx == samplingStep-1)
								{
									isMonitor = true;
									b_flag = true;
								}
								patternIdx = patternIdx++;
								time_cnt = 0;
								
							}//else
								
						}//if of time_cnt > Threshold/Inten
					}//if of measuredIntensity != 0
				}//if of get Sampling Step

				printf("Time = [%d]\t# of Detected Bot = [%d]\tsamplingRate. = [%.2f]\tmeasuredIntensity = [%.2f]\tsamplingStep = [%d]\tnumBotInOneSec = [%d]\tnumPktInOneSec = [%d]\tnumPktintoBF = [%d]\tfp = [%d]\tfp_BL = [%d]\t patternIdx = [%d]\t DABO_Cnt = [%d]\n",
					ip->getITime(), botDetectedCnt, samplingRate, measuredIntensity, samplingStep, numDetectedBotInOneSec, numPktInOneSec, numpktintoBF, fp_cnt, fp_BL, patternIdx, DABO_Cnt);
				fprintf(log_file, "Time = [%d]\t# of Detected Bot = [%d]\tsamplingRate. = [%.2f]\tmeasuredIntensity = [%.2f]\tsamplingStep = [%d]\tnumBotInOneSec = [%d]\tnumPktInOneSec = [%d]\tnumPktintoBF = [%d]\tfp = [%d]\tfp_BL = [%d]\t patternIdx = [%d]\t DABO_Cnt = [%d]\n",
					ip->getITime(), botDetectedCnt, samplingRate, measuredIntensity, samplingStep, numDetectedBotInOneSec, numPktInOneSec, numpktintoBF, fp_cnt, fp_BL, patternIdx, DABO_Cnt);
				
				DABO_Cnt = 0;		
				numDetectedBotInOneSec = 0;
				pre_time_int = now_time_int;
				numPktInOneSec=0;


				
			}
		
		}//else isMonitor
	}// end while
	


/*
	//Traffic파일 모두를 읽어들일 때까지 반복!//////////////////////////////////
	while (!feof(traffic_file))
	{
		IP_Select();

		ip_long = inet_addr((ip->getIP()));
		sprintf(ip_str, "%X\0", ip_long);
		numPktInOneSec++;
	
		//Get Bot's Intensity
		if (Bloom_BL->bloom_check(ip_str) > 0)
		{
			// shlee checkpoint

			double intensity = (ip->getTime() - lastContectedTime) * (double)(numDetectedBotInOneSec);
			lastContectedTime = ip->getTime();

			if (measuredIntensity < 0)
				measuredIntensity = intensity;
			else if (intensity > 0)
				measuredIntensity = 0.875*measuredIntensity + 0.125*(intensity); 
			
			numPktInOneSec--;
			continue;					//Packet Drop!
		}//if


		//Sampling Operation
		if (samplingStep > 0 && checkPattern(ip_long, samplingStep, patternIdx) == 0)
		{
			//it is not Sampling IP
			continue;
		}//end of Sampling Operation

		//해당 트래픽을 BloomFilter에 넣고 임계점을
		//넘지 않았다면 BloomFilter에 등록
		if (Bloom->bloom_check(ip_str) < Bloom->getMaxCount())
		{
			Bloom->bloom_add(ip_str);
			numPktforDABAO++;
			numpktintoBF++;
		}//if
		//해당 트래픽이 임계점(여기선4)를 넘었다면 블랙리스트에 추가
		else
		{
			Bloom_BL->bloom_add(ip_str);
			
			if (strcmp(ip->getType(), "Normal") == 0)
			{
				numDetectedBotInOneSec++;
				fp_cnt++;
			}//if
			else
			{
				botDetectedCnt++;
				numDetectedBotInOneSec++;
			}//else
				
		}//else
	
		//DABO
		if (numPktforDABAO > nminAverage)
		{
			Bloom->bloom_allDecrease();
			numPktforDABAO = 0;
			DABO_Cnt++;
		}//if of DABO


		//Get Sampling Step & Sampling Rate
		if (measuredIntensity >= 0 && numPktInOneSec > 0)
		{
			//해당 시간에 봇을 탐지 못한다면 Threshold/A만큼 기다려야 한다
			if (numDetectedBotInOneSec == 0)
				time_cnt++;
			else
				time_cnt = 0;
			if (measuredIntensity != 0)
			{
				if (time_cnt > (int)(sim_params->getCountThreshold() / measuredIntensity))
				{
					if (b_flag)
					{
						samplingRate = (double)((double)(nminAverage * measuredIntensity) / (double)(numPktInOneSec * 2));
						samplingStep = (int)ceil(1.0 / samplingRate);

						patternIdx = 0;
						b_flag = false;
						time_cnt = 0;
					}//if
					else
					{
						patternIdx = patternIdx++;
						time_cnt = 0;
					}//else
				}//if of time_cnt > Threshold/Inten
			}//if of measuredIntensity != 0
		}//if of get Sampling Step

		printf("Time = [%d]\t# of Detected Bot = [%d]\tsamplingRate. = [%.2f]\tmeasuredIntensity = [%.2f]\tsamplingStep = [%d]\tnumBotInOneSec = [%d]\tnumPktInOneSec = [%d]\tnumPktintoBF = [%d]\tfp = [%d]\tfp_BL = [%d]\t patternIdx = [%d]\t DABO_Cnt = [%d]\n",
			ip->getITime(), botDetectedCnt, samplingRate, measuredIntensity, samplingStep, numDetectedBotInOneSec, numPktInOneSec, numpktintoBF, fp_cnt, fp_BL, patternIdx, DABO_Cnt);
		fprintf(log_file, "Time = [%d]\t# of Detected Bot = [%d]\tsamplingRate. = [%.2f]\tmeasuredIntensity = [%.2f]\tsamplingStep = [%d]\tnumBotInOneSec = [%d]\tnumPktInOneSec = [%d]\tnumPktintoBF = [%d]\tfp = [%d]\tfp_BL = [%d]\t patternIdx = [%d]\t DABO_Cnt = [%d]\n",
			ip->getITime(), botDetectedCnt, samplingRate, measuredIntensity, samplingStep, numDetectedBotInOneSec, numPktInOneSec, numpktintoBF, fp_cnt, fp_BL, patternIdx, DABO_Cnt);
	
	}//while
*/	
	fprintf(log_file, "Detected bot = [%d], fp = [%d]", botDetectedCnt, fp_cnt);
	return 0.0;
}//Simulation_Start










//IP_Info에 할당된 메모리를 해제 한다.
void AD_CBF_Launcher::clearIPList()
{
	delete ip;
}


//BloomFilter에 할당된 메모리를 해제한다
void AD_CBF_Launcher::clearBloomFilter()
{
	Bloom->ClearBloomFilter();
	Bloom_BL->ClearBloomFilter();
}//clearBloomFilter



//////////////////////////////////////////////////////////////////////////
//checkPattern
//들어온 패킷이 Sampling Step에 해당하는지, 해당되지 않는지를 판단
int AD_CBF_Launcher::checkPattern(unsigned long long_ip, int samplingStep, int patternIdx)
{
	if (samplingStep == patternIdx + 1)
		this->b_flag = true;

	//들어온 IP는 SamplingStep에 해당되는 IP이다
	if ((long_ip % samplingStep) == patternIdx)
	{
		return 1;
	}//

	//들어온 IP는 SamplingStep에 해당되지 않는 IP이다
	return 0;
}//checkPattern



void delete_lastChar(char ** input)
{
	int len = strlen((*input));
	(*input)[len] = '\0';
	if ( (*input)[len - 1] == '\n')
		(*input)[len - 1] = '\0';
}//delete_lastChar