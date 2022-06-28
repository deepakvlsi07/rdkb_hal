/*
 * If not stated otherwise in this file or this component's Licenses.txt file the
 * following copyright and licenses apply:
 *
 * Copyright 2019 RDK Management
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "platform_hal.h" 

/* Note that 0 == RETURN_OK == STATUS_OK    */
/* Note that -1 == RETURN_ERR == STATUS_NOK */

INT platform_hal_GetDeviceConfigStatus(CHAR *pValue) { strcpy(pValue, "Complete"); return RETURN_OK; }

INT platform_hal_GetTelnetEnable(BOOLEAN *pFlag) { *pFlag = FALSE; return RETURN_OK; }
INT platform_hal_SetTelnetEnable(BOOLEAN Flag) { return RETURN_ERR; }
INT platform_hal_GetSSHEnable(BOOLEAN *pFlag) { *pFlag = FALSE; return RETURN_OK; }
INT platform_hal_SetSSHEnable(BOOLEAN Flag) { return RETURN_ERR; }

INT platform_hal_GetSNMPEnable(CHAR* pValue) { return RETURN_ERR; }
INT platform_hal_SetSNMPEnable(CHAR* pValue) { return RETURN_ERR; }
INT platform_hal_GetWebUITimeout(ULONG *pValue) { return RETURN_ERR; }
INT platform_hal_SetWebUITimeout(ULONG value) { return RETURN_ERR; }
INT platform_hal_GetWebAccessLevel(INT userIndex, INT ifIndex, ULONG *pValue) { return RETURN_ERR; }
INT platform_hal_SetWebAccessLevel(INT userIndex, INT ifIndex, ULONG value) { return RETURN_ERR; }

INT platform_hal_PandMDBInit(void) { return RETURN_OK; }
INT platform_hal_DocsisParamsDBInit(void) { return RETURN_OK; }
INT platform_hal_GetSerialNumber(CHAR* pValue) { strcpy(pValue, "Serial Number"); return RETURN_OK; }
INT platform_hal_GetHardwareVersion(CHAR* pValue) { strcpy(pValue, "Hardware Version"); return RETURN_OK; }
INT platform_hal_GetBootloaderVersion(CHAR* pValue, ULONG maxSize) { strcpy(pValue, "Bootloader Version"); return RETURN_OK; }
INT platform_hal_GetBaseMacAddress(CHAR *pValue) { strcpy(pValue, "BasMac"); return RETURN_OK; }
INT platform_hal_GetHardware(CHAR *pValue) { strcpy(pValue, "Hard"); return RETURN_OK; }

INT platform_hal_GetModelName(CHAR* pValue)
{
	FILE *fp = NULL;
	char buf[64] = {0};
	int count = 0;
  
	if (pValue == NULL)
	{
		return RETURN_ERR;
	}

	fp = popen("cat /proc/device-tree/model","r");
	if(fp == NULL)
	{
		return RETURN_ERR;
	}

	if(fgets(buf,sizeof(buf) -1,fp) != NULL)
	{
		for(count=0;buf[count]!='\n';count++) {
			pValue[count]=buf[count];
			if (count == sizeof(buf)-1) break;
		}
		pValue[count]='\0';
	}

	pclose(fp);
	
	return RETURN_OK; 
}

INT platform_hal_GetSoftwareVersion(CHAR* pValue, ULONG maxSize)
{
	FILE *fp;
	char buff[64]={0};
  
	if (pValue == NULL)
	{
		return RETURN_ERR;
	}

	if((fp = fopen("/version.txt", "r")) == NULL)
	{
		printf(("Error while opening the file version.txt \n"));
		return RETURN_ERR;
	}

	while(fgets(buff, 64, fp) != NULL)
	{
		if(strstr(buff, "VERSION") != NULL && strstr(buff, "YOCTO_VERSION") == NULL)
		{
			int i = 0;
			while((i < sizeof(buff)-8) && (buff[i+8] != '\n') && (buff[i+8] != '\r') && (buff[i+8] != '\0'))
			{
				pValue[i] = buff[i+8];
				i++;
			}
			pValue[i] = '\0';
			break;
		}
	}

	if(fp)
		fclose(fp);
	
	return RETURN_OK; 
}

INT platform_hal_GetFirmwareName(CHAR* pValue, ULONG maxSize)
{
	FILE *fp;
	char buff[64]={0};
  
	if (pValue == NULL)
	{
		return RETURN_ERR;
	}

	if((fp = fopen("/version.txt", "r")) == NULL)
	{
		printf(("Error while opening the file version.txt \n"));
		return RETURN_ERR;
	}

	while(fgets(buff, 64, fp) != NULL)
	{
		if(strstr(buff, "imagename") != NULL)
		{
			int i = 0;
			while((i < sizeof(buff)-10) && (buff[i+10] != '\n') && (buff[i+10] != '\r') && (buff[i+10] != '\0'))
			{
				pValue[i] = buff[i+10];
				i++;
			}
			pValue[i] = '\0';
			break;
		}
	}

	if(fp)
		fclose(fp);
	
	return RETURN_OK; 
}
INT platform_hal_GetTotalMemorySize(ULONG *pulSize) 
{ 
    char buf[64] = {0};
    char cmd[64] = {0};
    FILE *fp = NULL;

    sprintf(cmd, "awk '/MemTotal/ {print $2}' /proc/meminfo > /tmp/total_Mem");    
    system(cmd);

    fp = fopen("/tmp/total_Mem", "r");
    if(fp != NULL)
    {
        fgets(buf,sizeof(buf),fp);    
        fclose(fp);
        *pulSize = atoi(buf)/1024;
    }else{
        *pulSize = 0;
    }
     return RETURN_OK; 
}

INT platform_hal_GetHardware_MemUsed(CHAR *pValue)
{
    if (pValue == NULL)
    {
        return RETURN_ERR;
    }
    else
    {
        char buf[64] = {0};
        char cmd[64] = {0};
        FILE *fp = NULL;

        sprintf(cmd, "df > /tmp/flash_info");    
        system(cmd);
        sprintf(cmd, "awk '/ubi0/ {print $3}' /tmp/flash_info > /tmp/flash_used");
        system(cmd);
        unlink("/tmp/flash_info");

        fp = fopen("/tmp/flash_used", "r");
        if(fp != NULL)
        {
            fgets(buf,sizeof(buf),fp);    
            fclose(fp);
            unlink("/tmp/flash_used");
            sprintf(pValue,"%d",(atoi(buf)/1024));
        }else{
            *pValue = '0';
        }
        return RETURN_OK;
    }
}

INT platform_hal_GetHardware_MemFree(CHAR *pValue)
{
    if (pValue == NULL)
    {   
        return RETURN_ERR;
    }
    else
    {
        char buf[64] = {0};
        char cmd[64] = {0};
        FILE *fp = NULL;

        sprintf(cmd, "df > /tmp/flash_info");    
        system(cmd);
        sprintf(cmd, "awk '/ubi0/ {print $4}' /tmp/flash_info > /tmp/flash_free");
        system(cmd);
        unlink("/tmp/flash_info");

        fp = fopen("/tmp/flash_free", "r");
        if(fp != NULL)
        {
            fgets(buf,sizeof(buf),fp);    
            fclose(fp);
            unlink("/tmp/flash_free");
            sprintf(pValue,"%d",(atoi(buf)/1024));
        }else{
            *pValue = '0';
        }
        return RETURN_OK;
    }
}

INT platform_hal_GetFreeMemorySize(ULONG *pulSize)
{
    if (pulSize == NULL)
    {
        return RETURN_ERR;
    }
    char buf[64] = {0};
    char cmd[64] = {0};
    FILE *fp = NULL;

    sprintf(cmd, "awk '/MemFree/ {print $2}' /proc/meminfo > /tmp/free_Mem");    
    system(cmd);

    fp = fopen("/tmp/free_Mem", "r");
    if(fp != NULL)
    {
        fgets(buf,sizeof(buf),fp);    
        fclose(fp);
        *pulSize = atoi(buf)/1024;
    }else{
        *pulSize = 0;
    }
    return RETURN_OK;
}

INT platform_hal_GetUsedMemorySize(ULONG *pulSize)
{
    if (pulSize == NULL)
    {
        return RETURN_ERR;
    }

    unsigned long total = 0;
    unsigned long free = 0;
    platform_hal_GetFreeMemorySize(&free);
    platform_hal_GetTotalMemorySize(&total);
    *pulSize = (total-free);
    return RETURN_OK;
}

INT platform_hal_GetFactoryResetCount(ULONG *pulSize)
{
        if (pulSize == NULL)
        {
           return RETURN_ERR;
        }
        *pulSize = 2;
        return RETURN_OK;
}

INT platform_hal_ClearResetCount(BOOLEAN bFlag)
{
        return RETURN_OK;
}

INT platform_hal_getTimeOffSet(CHAR *pValue)
{ 
	return RETURN_OK; 
} 

INT platform_hal_SetDeviceCodeImageTimeout(INT seconds)
{ 
	return RETURN_OK; 
} 

INT platform_hal_SetDeviceCodeImageValid(BOOLEAN flag)
{ 
	return RETURN_OK; 
}

INT platform_hal_getCMTSMac(CHAR *pValue)
{
     if (pValue == NULL)
     {
         return RETURN_ERR;
     }
    strcpy(pValue,"00:00:00:00:00:00");
    return RETURN_OK;
}

/* platform_hal_SetSNMPOnboardRebootEnable() function */
/**
* @description : Set SNMP Onboard Reboot Enable value
*                to allow or ignore SNMP reboot
* @param IN    : pValue - SNMP Onboard Reboot Enable value
                 ("disable" or "enable")
*
* @return      : The status of the operation
* @retval      : RETURN_OK if successful
* @retval      : RETURN_ERR if any error is detected
*/
INT platform_hal_SetSNMPOnboardRebootEnable(CHAR* pValue)
{
	return RETURN_OK;
}
INT platform_hal_GetRouterRegion(CHAR* pValue)
{
	return RETURN_OK;
}

char ifname[32];
char *get_current_wan_ifname()
{
	FILE *fp = NULL;
	char command[128] = {0};
	char ert_ifname[32] = {0};
	snprintf(command, 128, "sysevent get %s", "current_wan_ifname");
	fp = popen(command, "r");
	if (fp == NULL)
	{
		return "0";
	}
	if (fgets(ert_ifname, sizeof(ert_ifname), fp) != NULL)
	{
		if(strlen(ert_ifname) == 0){
			fprintf(stderr, "%s %d syseventError %d\n", __FUNCTION__, __LINE__, RETURN_ERR);
			pclose(fp);
			return "0";
		}
	}	
	pclose(fp);
	memset(ifname, 0, sizeof(ifname));
	strncpy(ifname, ert_ifname, strlen(ert_ifname)-1);

	return ifname;
}



INT platform_hal_GetDhcpv6_Options ( dhcp_opt_list ** req_opt_list, dhcp_opt_list ** send_opt_list)
{
	if ((req_opt_list == NULL) || (send_opt_list == NULL))    
	{
		return RETURN_ERR;
	}

	return RETURN_OK;
}



INT platform_hal_GetDhcpv4_Options ( dhcp_opt_list ** req_opt_list, dhcp_opt_list ** send_opt_list)
{
	if ((req_opt_list == NULL) || (send_opt_list == NULL))    
	{
		return RETURN_ERR;
	}

	return RETURN_OK;
}

