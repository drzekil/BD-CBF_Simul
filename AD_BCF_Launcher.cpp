#include"AD_BCF_Launcher.h"

void delete_lastChar(char ** input);


//////////////////////////////////////////////////////////////
//Default Constructor
//BloomFilter�� �迭�� �����Ѵ�.
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
	
	//IP������ �ӽ� �����ϴ� ��ü ����
	ip = new IP_Info;
	
	//����ȯ�� ����(sim_params)����
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
}//�Ҹ���

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


//BloomFilter��, ����ȯ�氪�� ����/////////////////////////////
void AD_CBF_Launcher::BloomFilter_Setting()
{
	//sim_params�� �̿��Ͽ� BloomFilter�� ������ �ʱ�ȭ
	Bloom->setParam( sim_params->getMSize(), sim_params->getCountThreshold(), sim_params->getNFuncs(), SAXHash, RSHash, JSHash, BKDRHash, APHash, FNVHash, SDBMHash, DJBHash);
	Bloom_BL->setParam( sim_params->getMSize(), sim_params->getCountThreshold(), sim_params->getNFuncs(), SAXHash, RSHash, JSHash, BKDRHash, APHash, FNVHash, SDBMHash, DJBHash);
}//


//IP_Select/////////////////////////////////////////////
//�α� ���Ϸκ��� 1 Line�� �о�鿩 ���⼭ ���� ������ Parsing��
// ip����� ����.
void AD_CBF_Launcher :: IP_Select()
{
	char * time_tmp;
	char * ip_tmp;
	char * type_tmp;
	char token[2] = "\t";
	double t_tmp;
	int i_tmp;

	//���Ͽ��� 1Line�� �о� ���δ�.
	fgets(buffer, 256, traffic_file);
	
	//token�� �̿��� time, ip, type�� �����Ѵ�.
	time_tmp = strtok(buffer, token);
	ip_tmp = strtok(NULL, token);
	type_tmp = strtok(NULL, token);
	
	//IP���ڿ��� �Ǹ������� \0 ����
	delete_lastChar(&type_tmp);
	
	//ip���� �Է�
	ip->setIP(ip_tmp);
	ip->setType(type_tmp);
	
	//time �Է�
	t_tmp = strtod(time_tmp, NULL);
	ip->setTime(t_tmp);
	
	//i_time �Է�
	i_tmp = (int)(ip->getTime() * 1000); 
	ip->setITime(i_tmp);
	
	//cout << ip->getTime() << "\t" << ip->getITime() << "\t" <<ip->getIP() << "\t" << ip->getType() << endl;

}//IP_Select


////////////////////////////////////////////////////////////////////////////////
//���������� BloomFilter�� DDoS������ Ž���ϰ�, �̸� ����ϴ� ��ƾ.
//IP_Select���� �о���� 1 Line�� ip�� Ž���׹�� ��ƾ�� �����Ѵ�.
double AD_CBF_Launcher::Simulation_Start()
{
	unsigned long ip_long;
	char ip_str[IP_BUFFER_SIZE];

	unsigned int botDetectedCnt = 0;				//������ �Ǹ� IP�� ����
	unsigned int DABO_Cnt = 0;						//DABO�� �Ͼ Ƚ��
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
		
		numPktInOneSec++;						//1�ʿ� ���� IP���� ����

		if (isMonitor)
		{
			numPktforDABAO++;						//�ٺ��� ����Ű�� ���� ���� Packet �� ����


			//���Ϳ� IP�� �ְ� Threshold���� �Ѿ������� �˻��Ѵ�.
			//���� �ʾҴٸ� ���Ϳ� ����ϰ�, �Ѿ��ٸ� nDabo�� nminAverage�� ����Ѵ�
			if (Bloom->bloom_check(ip_str) < Bloom->getMaxCount())
			{
				Bloom->bloom_add(ip_str);
				numpktintoBF++;
			}//if
			else
			{
				//ó������ Threshold���� �Ѱ��� ���� ���ݱ��� ���� ��Ŷ�� ������ �Ѵ�
				//�������� MovingAverage������ nDabo���� ����Ѵ�.
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
	
			//�ش� Ʈ������ BloomFilter�� �ְ� �Ӱ�����
			//���� �ʾҴٸ� BloomFilter�� ���
			else if (Bloom->bloom_check(ip_str) < Bloom->getMaxCount())
			{
				Bloom->bloom_add(ip_str);
				numPktforDABAO++;
				numpktintoBF++;

				fprintf(log_pass_file, "%f\t%s\t%s\t\n",ip->getTime(), ip->getIP(), ip->getType());
			}//if
			//�ش� Ʈ������ �Ӱ���(���⼱4)�� �Ѿ��ٸ� ������Ʈ�� �߰�
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
					//�ش� �ð��� ���� Ž�� ���Ѵٸ� Threshold/A��ŭ ��ٷ��� �Ѵ�
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
	//Traffic���� ��θ� �о���� ������ �ݺ�!//////////////////////////////////
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

		//�ش� Ʈ������ BloomFilter�� �ְ� �Ӱ�����
		//���� �ʾҴٸ� BloomFilter�� ���
		if (Bloom->bloom_check(ip_str) < Bloom->getMaxCount())
		{
			Bloom->bloom_add(ip_str);
			numPktforDABAO++;
			numpktintoBF++;
		}//if
		//�ش� Ʈ������ �Ӱ���(���⼱4)�� �Ѿ��ٸ� ������Ʈ�� �߰�
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
			//�ش� �ð��� ���� Ž�� ���Ѵٸ� Threshold/A��ŭ ��ٷ��� �Ѵ�
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










//IP_Info�� �Ҵ�� �޸𸮸� ���� �Ѵ�.
void AD_CBF_Launcher::clearIPList()
{
	delete ip;
}


//BloomFilter�� �Ҵ�� �޸𸮸� �����Ѵ�
void AD_CBF_Launcher::clearBloomFilter()
{
	Bloom->ClearBloomFilter();
	Bloom_BL->ClearBloomFilter();
}//clearBloomFilter



//////////////////////////////////////////////////////////////////////////
//checkPattern
//���� ��Ŷ�� Sampling Step�� �ش��ϴ���, �ش���� �ʴ����� �Ǵ�
int AD_CBF_Launcher::checkPattern(unsigned long long_ip, int samplingStep, int patternIdx)
{
	if (samplingStep == patternIdx + 1)
		this->b_flag = true;

	//���� IP�� SamplingStep�� �ش�Ǵ� IP�̴�
	if ((long_ip % samplingStep) == patternIdx)
	{
		return 1;
	}//

	//���� IP�� SamplingStep�� �ش���� �ʴ� IP�̴�
	return 0;
}//checkPattern



void delete_lastChar(char ** input)
{
	int len = strlen((*input));
	(*input)[len] = '\0';
	if ( (*input)[len - 1] == '\n')
		(*input)[len - 1] = '\0';
}//delete_lastChar