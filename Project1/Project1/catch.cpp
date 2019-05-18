/*
构造并发送ARP包
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
	/* 获取设备列表 */

	if (argc != 6)//argc==5,及程序后面有四个参数
	{
		printf("usage: %s inerface", argv[0]);
		return -1;
	}


	if (pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}

	/* 数据列表 */
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
		printf("\n找不到网卡! 检查是否安装WinPcap.\n");
		return -1;
	}
	printf("Enter the interface number (1-%d):", i);
	scanf_s("%d", &inum);
	if (inum < 1 || inum > i)
	{
		printf("\nInterface number out of range.\n");
		/* 释放设备列表 */
		pcap_freealldevs(alldevs);
		return -1;
	}
	/* 转到选择的设备 */
	for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);
	/* 打开设备 */
	if ((adhandle = pcap_open_live(d->name, //设备名 
		65536, // 最大捕捉字节数 
		1, // 混杂模式 
		1000, // 读入超时 
		errbuf // 错误缓冲 
	)) == NULL)
	{
		/*打开失败*/
		fprintf(stderr, "\n打开失败. %s 不被winpcap支持\n", d->name);
		/* 释放列表 */
		pcap_freealldevs(alldevs);
		return -1;
	}
	/* 释放设备列表 */
	pcap_freealldevs(alldevs);

	/* 填充数据段 */

	//flag为1表示ARP请求
	if ('1' == argv[4][0])
	{
		//源MAC地址
		k = 0;
		for (i = 0; i < 18; i = i + 3)
		{
			temp[0] = (int)argv[3][i];
			temp[1] = (int)argv[3][i + 1];
			if (temp[0] > 96)         //当输入mac为小写字母时字符转换为16进制
				temp[0] = temp[0] - 87;
			else if (temp[0] > 64)
				temp[0] = temp[0] - 55;//当输入mac为大写字母时字符转换为16进制
			else
				temp[0] = temp[0] - 48;//当输入mac为数字时字符转换为16进制
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
		//发送ARP请求时目的MAC全置为ff
		for (i = 0; i < 6; i++)
		{
			packet[i] = packet[32 + i] = 0xff;
		}
		*/
		//目的MAC地址
		k = 0;
		for (i = 0; i < 18; i = i + 3)
		{
			temp[0] = (int)argv[5][i];
			temp[1] = (int)argv[5][i + 1];
			if (temp[0] > 96)         //当输入mac为小写字母时字符转换为16进制
				temp[0] = temp[0] - 87;
			else if (temp[0] > 64)
				temp[0] = temp[0] - 55;//当输入mac为大写字母时字符转换为16进制
			else
				temp[0] = temp[0] - 48;//当输入mac为数字时字符转换为16进制
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

	//flag=2:ARP应答
	else
	{
		//目的MAC地址
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
		
		//应答ARP请求时把源MAC置为0
		for (i = 0; i < 6; i++)
		{
			packet[6 + i] = packet[22 + i] = 0x00;
		}
		




	}

	//源IP地址
	k = 0;
	temp[2] = 0;  //指向每个字节初始位置
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
				//当遇到小数点时，j自加1目的是让temp[2]+j指向下一字节的第一位
				j++;
				break;
			}
		}
		packet[28 + k] = temp[1];	//4次temp[1]的值为：172 20 10 6
		
		k++;
		temp[2] += j;	//每次temp[2]的值为：0 4 7 10，保证了每次指向下一字节的第一位
	}
	//目标IP地址
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
	//ARP首部
	packet[12] = 0x08;//12、13位为帧类型
	packet[13] = 0x06;
	packet[14] = 0x00;//14、15位为硬件类型
	packet[15] = 0x01;
	packet[16] = 0x08;//16、17位为协议类型
	packet[17] = 0x00;
	packet[18] = 0x06;//硬件地址长度
	packet[19] = 0x04;//协议地址长度
	packet[20] = 0x00;//op
	packet[21] = (int)argv[4][0] - 48;//op(1为请求2为应答)


    /* 填充发送包的剩余部分 */
	for (i = 0; i < 18; i++)
	{
		packet[42 + i] = 0;
	}
	//这里后四个字节本应该是校验位,这里就不算了，写个日期纪念一下
	packet[60] = 0x20;
	packet[61] = 0x19;
	packet[62] = 0x05;
	packet[63] = 0x10;
	/* 发送包 */
	pcap_sendpacket(adhandle, packet, 64);
	printf("Success!\n");

	getchar();
	return 0;
}
