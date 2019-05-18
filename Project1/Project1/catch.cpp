/*
���첢����ARP��
*/

#define WIN32
#include "pcap.h"
#include <stdlib.h>
#include <stdio.h>

#pragma comment(lib, "wpcap.lib")
#pragma comment(lib, "wsock32.lib")
#pragma comment(lib, "ws2_32.lib")

int main(int argc, char** argv)
{
	unsigned char packet[100];
	pcap_if_t* alldevs;
	pcap_if_t* d;
	int inum;
	int i = 0, j, k, temp[3];
	pcap_t* adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];
	/* ��ȡ�豸�б� */

	if (argc != 6)//argc==5,������������ĸ�����
	{
		printf("usage: %s inerface", argv[0]);
		return -1;
	}


	if (pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}

	/* �����б� */
	for (d = alldevs; d; d = d->next)
	{
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}
	if (i == 0)
	{
		printf("\n�Ҳ�������! ����Ƿ�װWinPcap.\n");
		return -1;
	}
	printf("Enter the interface number (1-%d):", i);
	scanf_s("%d", &inum);
	if (inum < 1 || inum > i)
	{
		printf("\nInterface number out of range.\n");
		/* �ͷ��豸�б� */
		pcap_freealldevs(alldevs);
		return -1;
	}
	/* ת��ѡ����豸 */
	for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);
	/* ���豸 */
	if ((adhandle = pcap_open_live(d->name, //�豸�� 
		65536, // ���׽�ֽ��� 
		1, // ����ģʽ 
		1000, // ���볬ʱ 
		errbuf // ���󻺳� 
	)) == NULL)
	{
		/*��ʧ��*/
		fprintf(stderr, "\n��ʧ��. %s ����winpcap֧��\n", d->name);
		/* �ͷ��б� */
		pcap_freealldevs(alldevs);
		return -1;
	}
	/* �ͷ��豸�б� */
	pcap_freealldevs(alldevs);

	/* ������ݶ� */

	//flagΪ1��ʾARP����
	if ('1' == argv[4][0])
	{
		//ԴMAC��ַ
		k = 0;
		for (i = 0; i < 18; i = i + 3)
		{
			temp[0] = (int)argv[3][i];
			temp[1] = (int)argv[3][i + 1];
			if (temp[0] > 96)         //������macΪСд��ĸʱ�ַ�ת��Ϊ16����
				temp[0] = temp[0] - 87;
			else if (temp[0] > 64)
				temp[0] = temp[0] - 55;//������macΪ��д��ĸʱ�ַ�ת��Ϊ16����
			else
				temp[0] = temp[0] - 48;//������macΪ����ʱ�ַ�ת��Ϊ16����
			if (temp[1] > 96)
				temp[1] = temp[1] - 87;
			else if (temp[1] > 64)
				temp[1] = temp[1] - 55;
			else
				temp[1] = temp[1] - 48;
			packet[22 + k] = packet[6 + k] = temp[0] * 16 + temp[1];
			k++;
		}
		/*
		//����ARP����ʱĿ��MACȫ��Ϊff
		for (i = 0; i < 6; i++)
		{
			packet[i] = packet[32 + i] = 0xff;
		}
		*/
		//Ŀ��MAC��ַ
		k = 0;
		for (i = 0; i < 18; i = i + 3)
		{
			temp[0] = (int)argv[5][i];
			temp[1] = (int)argv[5][i + 1];
			if (temp[0] > 96)         //������macΪСд��ĸʱ�ַ�ת��Ϊ16����
				temp[0] = temp[0] - 87;
			else if (temp[0] > 64)
				temp[0] = temp[0] - 55;//������macΪ��д��ĸʱ�ַ�ת��Ϊ16����
			else
				temp[0] = temp[0] - 48;//������macΪ����ʱ�ַ�ת��Ϊ16����
			if (temp[1] > 96)
				temp[1] = temp[1] - 87;
			else if (temp[1] > 64)
				temp[1] = temp[1] - 55;
			else
				temp[1] = temp[1] - 48;
			packet[32 + k] = packet[0 + k] = temp[0] * 16 + temp[1];
			k++;
		}




	}

	//flag=2:ARPӦ��
	else
	{
		//Ŀ��MAC��ַ
		k = 0;
		for (i = 0; i < 18; i = i + 3)
		{
			temp[0] = (int)argv[3][i];
			temp[1] = (int)argv[3][i + 1];
			if (temp[0] > 96)
				temp[0] = temp[0] - 87;
			else if (temp[0] > 64)
				temp[0] = temp[0] - 55;
			else
				temp[0] = temp[0] - 48;
			if (temp[1] > 96)
				temp[1] = temp[1] - 87;
			else if (temp[1] > 64)
				temp[1] = temp[1] - 55;
			else
				temp[1] = temp[1] - 48;
			packet[k] = packet[32 + k] = temp[0] * 16 + temp[1];
			k++;
		}
		
		//Ӧ��ARP����ʱ��ԴMAC��Ϊ0
		for (i = 0; i < 6; i++)
		{
			packet[6 + i] = packet[22 + i] = 0x00;
		}
		




	}

	//ԴIP��ַ
	k = 0;
	temp[2] = 0;  //ָ��ÿ���ֽڳ�ʼλ��
	for (i = 0; i < 4; i++)
	{
		temp[0] = 0;
		temp[1] = 0;
		for (j = 0; j < 4; j++)
		{
			if (argv[1][j + temp[2]] >= '0' && argv[1][j + temp[2]] <= '9')
			{
				temp[0] = (int)argv[1][j + temp[2]] - 48;
				temp[1] = temp[1] * 10 + temp[0];
				printf("%d %d\n",temp[0],temp[1]);
			}
			else
			{
				//������С����ʱ��j�Լ�1Ŀ������temp[2]+jָ����һ�ֽڵĵ�һλ
				j++;
				break;
			}
		}
		packet[28 + k] = temp[1];	//4��temp[1]��ֵΪ��172 20 10 6
		
		k++;
		temp[2] += j;	//ÿ��temp[2]��ֵΪ��0 4 7 10����֤��ÿ��ָ����һ�ֽڵĵ�һλ
	}
	//Ŀ��IP��ַ
	k = 0;
	temp[2] = 0;
	for (i = 0; i < 4; i++)
	{
		temp[0] = 0;
		temp[1] = 0;
		for (j = 0; j < 4; j++)
		{
			if (argv[2][j + temp[2]] >= '0' && argv[2][j + temp[2]] <= '9')
			{
				temp[0] = (int)argv[2][j + temp[2]] - 48;
				temp[1] = temp[1] * 10 + temp[0];
				//printf("%d %d\n",temp[0],temp[1]);
			}
			else
			{
				j++;
				break;
			}
		}
		packet[38 + k] = temp[1];
		k++;
		temp[2] += j;
	}
	//ARP�ײ�
	packet[12] = 0x08;//12��13λΪ֡����
	packet[13] = 0x06;
	packet[14] = 0x00;//14��15λΪӲ������
	packet[15] = 0x01;
	packet[16] = 0x08;//16��17λΪЭ������
	packet[17] = 0x00;
	packet[18] = 0x06;//Ӳ����ַ����
	packet[19] = 0x04;//Э���ַ����
	packet[20] = 0x00;//op
	packet[21] = (int)argv[4][0] - 48;//op(1Ϊ����2ΪӦ��)


    /* ��䷢�Ͱ���ʣ�ಿ�� */
	for (i = 0; i < 18; i++)
	{
		packet[42 + i] = 0;
	}
	//������ĸ��ֽڱ�Ӧ����У��λ,����Ͳ����ˣ�д�����ڼ���һ��
	packet[60] = 0x20;
	packet[61] = 0x19;
	packet[62] = 0x05;
	packet[63] = 0x10;
	/* ���Ͱ� */
	pcap_sendpacket(adhandle, packet, 64);
	printf("Success!\n");

	getchar();
	return 0;
}
