#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <string.h>
#include <unistd.h>

#define BUFLEN 100
#define GET 0
#define GETNEXT 1
#define SET 2

/*
    Authors: Matthew Somers and Erik Holden for CS166.
    Based on the example from:
    http://www.net-snmp.org/wiki/index.php/TUT:Simple_Application
*/

/*
    TODO:
    Analyze accuracy report for extra credit.
*/

netsnmp_pdu *makepdu(char myoid[], int getornext);
char **findAllAddrs(netsnmp_session *ss, 
    int **alladdrs[BUFLEN][BUFLEN], int icounter);
void monitor(netsnmp_session *ss, char oid[], int numsamples, int secondsinterval);
char *makegraphstring(char **graph[BUFLEN][BUFLEN], float latestspeed, int time);

int main(int argc, char ** argv)
{
    //check args
    if (argc != 4)
    {
        printf("\nUsage: %s secondsinterval numsamples ip\n\n", argv[0]);
        return 1;
    }

    int secondsinterval = atoi(argv[1]);
    int numsamples = atoi(argv[2]);

    if (numsamples > 20)
    {
        printf("\nPlease enter a lower number of samples!\n\n");
        return 1;
    }
    
    if (secondsinterval < 1)
    {
        printf("\nInvalid seconds interval.\n\n");
        return 1;
    }

    netsnmp_session session, *ss;
    netsnmp_pdu *response;
    netsnmp_variable_list *vars;
    int status;

    //Initialize the SNMP library
    init_snmp("snmpapp");

    //Initialize a "session" that defines who we're going to talk to
    snmp_sess_init( &session );
    //set up defaults
    session.peername = strdup(argv[3]);
    
    //we'll use the insecure (but simplier) SNMPv1
    //set the SNMP version number
    session.version = SNMP_VERSION_1;

    //set the SNMPv1 community name used for authentication
    session.community = "public";
    session.community_len = strlen(session.community);

    //SNMPv1
    //Open the session
    SOCK_STARTUP;
    ss = snmp_open(&session);

    //establish the session
    if (!ss) 
    {
        snmp_sess_perror("ack", &session);
        SOCK_CLEANUP;
        exit(1);
    }


    //holds all of our interface info
    int icounter;
    int inumholder[BUFLEN];
    char inameholder[BUFLEN][BUFLEN];
    char *iipholder[icounter][BUFLEN];

    //get interfaces loop-------------------------------
    //goes until it finds 100 or fails finding ifDescrs (interfaces)
    for (icounter = 0; icounter < BUFLEN; icounter++)
    {
        //most comments are in monitoring section
        char myoidnum[BUFLEN];
        char myoidname[BUFLEN];
        sprintf(myoidname, "ifDescr.%d", icounter+1);
        sprintf(myoidnum, "ifIndex.%d", icounter+1);

        netsnmp_pdu *pduname = makepdu(myoidname, GET);
        netsnmp_pdu *pdunum = makepdu(myoidnum, GET);

        status = snmp_synch_response(ss, pduname, &response);
        if (status == STAT_SUCCESS 
            && response->errstat == SNMP_ERR_NOERROR) 
        {
            //save this interface!
            vars = response->variables;
            sprintf(inameholder[icounter], vars->val.string);
            status = snmp_synch_response(ss, pdunum, &response);
            vars = response->variables;
            inumholder[icounter] = *vars->val.integer;           
        }

        else //failed finding next ifDescr
        {
            if (response)
                snmp_free_pdu(response);
            break; //IMPORTANT escape conditions
        }

        if (response)
            snmp_free_pdu(response);
    }

    //find all ips--------------------------------------
    char **alladdrs[BUFLEN][BUFLEN];
    findAllAddrs(ss, alladdrs, icounter);

    //go through interfaces, match up with ips-----------------
    int m;

    //print top of table
    printf("\nINTERFACES\n-------------------------------------------------\n|     index\t|      name\t|   ip address\t|\n");
    printf("|-----------------------------------------------|\n");

    for (m = 0; m < icounter; m++) 
    {
        //specific to local loop
        if (strcmp(inameholder[m], "lo") == 0)
        { 
            strcpy(iipholder[m], "local loop");
            printf("|        %d\t|       %s\t|  local loop\t|\n", inumholder[m], inameholder[m]);
            continue;
        } 

        int j;
        //iterate through ips to match up with interfaces
        for (j = 0; j < icounter; j++)
        {
            char *ipcompareoid[BUFLEN];
            sprintf(ipcompareoid, "ipAdEntIfIndex.%s", alladdrs[j]);
            //printf("\n\n%s\n\n", ipcompareoid);
            netsnmp_pdu *pdutocompare = makepdu(ipcompareoid, GET);
            status = snmp_synch_response(ss, pdutocompare, &response);

            if (status == STAT_SUCCESS 
                && response->errstat == SNMP_ERR_NOERROR)
            {
                vars = response->variables;
                int ivars = *vars->val.integer;
                if (inumholder[m] == ivars)
                {
                    strcpy(iipholder[m], alladdrs[j]);
                    printf("|        %d\t|       %s\t|  %s\t|\n", inumholder[m], inameholder[m], alladdrs[j]);
                    break; 
                } 
            }

            //on a broken ip
            else
            {
                //catches the interfaces without ips
                if (j == (icounter-1))
                {
                    strcpy(iipholder[m], "");
                    printf("|        %d\t|       %s\t|     no ip\t|\n", inumholder[m], inameholder[m]);
                    break;
                }
            }
        }
    }

    printf("-------------------------------------------------\n\n");

    //get ip neighbors loop----------------------------
    
    printf("\nNEIGBORS:\n---------------------------------\n|   interface \t|   ip address\t|\n");
    printf("|-------------------------------|\n");

    for(m = 1; m <= icounter; m++)
    {
        char neighborOID[BUFLEN];
        sprintf(neighborOID, "ipNetToMediaIfIndex.%d", m);
        
        //initialize pdus
        netsnmp_pdu *neighbor_pdu;
        neighbor_pdu = makepdu(neighborOID, GETNEXT);
        netsnmp_pdu *neighbor_response;

        //get response and status
        int neighbor_status = snmp_synch_response(ss, neighbor_pdu, &neighbor_response);
        
        if (neighbor_status == STAT_SUCCESS 
            && neighbor_response->errstat == SNMP_ERR_NOERROR) 
        {
            netsnmp_variable_list *neighbor_vars;
  
            neighbor_vars = neighbor_response->variables;
            //interface index
            int ifInd = *neighbor_vars->val.integer;

            //if the interface index is the current counter
            if(m == ifInd)
            {
                char neighborIPOID_orig[BUFLEN];
                char neighborIPOID[BUFLEN];
                sprintf(neighborIPOID_orig, "ipNetToMediaNetAddress.%d", m);
                sprintf(neighborIPOID, "ipNetToMediaNetAddress.%d", m);

                while(1)//loops until there are no new ip addresses
                {
                    //initialize pdus
                    neighbor_pdu = makepdu(neighborIPOID, GETNEXT);

                    //get response and status
                    neighbor_status = snmp_synch_response(ss, neighbor_pdu, &neighbor_response);

                    if (neighbor_status == STAT_SUCCESS 
            && neighbor_response->errstat == SNMP_ERR_NOERROR) 
                    {
                        
                        //Looks for an ip address on the interface
                        neighbor_vars = neighbor_response->variables;
                        size_t netAddrLen = MAX_OID_LEN;
                        oid netAddrOID[MAX_OID_LEN];
                        char *oidstring = "ipNetToMediaNetAddress";
                        snmp_parse_oid(oidstring, netAddrOID, &netAddrLen);
                        int strcmplen = 10;//1.3.6.1.2.1.4.22.1

                        //checks if the oid type is an ip address
                        if(snmp_oid_compare(netAddrOID, strcmplen, neighbor_vars->name, strcmplen) == 0)
                        {
                            //print_variable(neighbor_vars->name, neighbor_vars->name_length, neighbor_vars);
                            //construct ip address into string
                            u_char *addr = neighbor_vars->val.string;
                            char ipaddr[BUFLEN];
                            char iptemp[BUFLEN];
                            sprintf(ipaddr, "%d", addr[0]);
                            strcat(ipaddr, ".");
                            sprintf(iptemp, "%d", addr[1]);
                            strcat(ipaddr, iptemp);
                            strcat(ipaddr, ".");
                            sprintf(iptemp, "%d", addr[2]);
                            strcat(ipaddr, iptemp);
                            strcat(ipaddr, ".");
                            sprintf(iptemp, "%d", addr[3]);
                            strcat(ipaddr, iptemp);

                            printf("|       %d\t| %s\t|\n", m, ipaddr);

                            //construct next oid by concatenating ip address
                            char nextOID[BUFLEN];
                            sprintf(nextOID, "%s.", neighborIPOID_orig);
                            strcat(nextOID, ipaddr);
                            sprintf(neighborIPOID, nextOID);
                        }
                        else//if it does not find an ip address then stop searching (move to next interface)
                            break;
                    }
                }
            }
        }
        else//no more interfaces; break loop
        {
            break;
        }

    }
        printf("---------------------------------\n\n");


    //set agent to update more often (every 1 second):
    char setoid[] = ("nsCacheTimeout.1.3.6.1.2.1.2.2");
    netsnmp_pdu *setpdu = makepdu(setoid, SET);
    snmp_synch_response(ss, setpdu, &response);


    //MONITORING LOOP!----------------------------------
    for (m = 0; m < icounter; m++)
    {
        char inoid[BUFLEN];
        char outoid[BUFLEN];
        sprintf(inoid, "ifInOctets.%d", inumholder[m]);
        sprintf(outoid, "ifOutOctets.%d", inumholder[m]);

        printf("\n\n%s's kilobits in per second:\n", inameholder[m]);
        monitor(ss, inoid, numsamples, secondsinterval);
        printf("\n\n%s's kilobits out per second:\n", inameholder[m]);
        monitor(ss, outoid, numsamples, secondsinterval);
        printf("\n\n");
    }

    snmp_close(ss);
    SOCK_CLEANUP;
    return (0);
}

void monitor(netsnmp_session *ss, char oid[], int numsamples, int secondsinterval)
{
    int m;
    netsnmp_pdu *response;
    netsnmp_variable_list *vars;
    int status;
    int last;
    int current;
    char **graph[BUFLEN][BUFLEN];
    int i;
    int j;

    //build graph
    for (i = 0; i < BUFLEN; i++)
        for (j = 0; j < BUFLEN; j++)
            graph[i][j] = '\0';

    //sprintf(graph[0], "\n2240|");
    sprintf(graph[0], "\n1920|");
    sprintf(graph[1], "\n1600|");
    sprintf(graph[2], "\n1280|");
    sprintf(graph[3], "\n 960|");
    sprintf(graph[4], "\n 640|");
    sprintf(graph[5], "\n 320|");
    sprintf(graph[6], "\n   0|");
    sprintf(graph[7], "\n    |");

    //build bottom row of graph
    sprintf(graph[8], "\n    0");
    for (i = 0; i < numsamples; i++)
    {
        if (i == numsamples-1)
            strcat(graph[7], "-");
        strcat(graph[7], "---");
        if (i >= 10)
            strcat(graph[8], " ");
        else
            strcat(graph[8], "  ");
        int multiple = secondsinterval*(i+1);
        char *smultiple[BUFLEN];
        sprintf(smultiple, "%d", multiple);
        strcat(graph[8], smultiple);
    }
    strcat(graph[8], " (seconds)");

    //actually monitor
    for (m = 0; m <= numsamples; m++)
    {
        //a brand new pdu is required for each.
        netsnmp_pdu *pdu = makepdu(oid, GET);

        //Send the Request out.
        status = snmp_synch_response(ss, pdu, &response);

        //Process the response.
        if (status == STAT_SUCCESS 
            && response->errstat == SNMP_ERR_NOERROR) 
        {
            vars = response->variables;

            //need 2 points to do graph, skip first
            if (m == 0)
            {
                last = *vars->val.integer;
                printf("\r%s", makegraphstring(graph, 0.0, m));
            }
            else
            {
                current = *vars->val.integer;
                float speed = (current-last);
                last = current;
                speed *= 8.0;
                speed /= 1000.0;
                speed /= secondsinterval;
                //printf("dec speed: %d, float speed: %f\n", (current-last), speed);
                printf("\r%s", makegraphstring(graph, speed, m));   
            }

            fflush(stdout);
            if (m != numsamples)
                printf("\033[9A"); //move console cursor up 9 lines
        }

        //clean up
        if (response)
            snmp_free_pdu(response);

        //take a break
        sleep(secondsinterval);
    }
}

char *makegraphstring(char **graph[BUFLEN][BUFLEN], float latestspeed, int time)
{
    char *graphstring[BUFLEN*BUFLEN];
    sprintf(graphstring, "");

    //modify graph with new data
    if (time != 0)
    {
        if (latestspeed >= 1920)
        {
            strcat(graph[0], "  *");
            strcat(graph[1], "  *");
            strcat(graph[2], "  *");
            strcat(graph[3], "  *");
            strcat(graph[4], "  *");
            strcat(graph[5], "  *");
            strcat(graph[6], "  *");
        }
        else if (latestspeed >= 1600)
        {
            strcat(graph[0], "   ");
            strcat(graph[1], "  *");
            strcat(graph[2], "  *");
            strcat(graph[3], "  *");
            strcat(graph[4], "  *");
            strcat(graph[5], "  *");
            strcat(graph[6], "  *");
        }
        else if (latestspeed >= 1280)
        {
            strcat(graph[0], "   ");
            strcat(graph[1], "   ");
            strcat(graph[2], "  *");
            strcat(graph[3], "  *");
            strcat(graph[4], "  *");
            strcat(graph[5], "  *");
            strcat(graph[6], "  *");
        }
        else if (latestspeed >= 960)
        {
            strcat(graph[0], "   ");
            strcat(graph[1], "   ");
            strcat(graph[2], "   ");
            strcat(graph[3], "  *");
            strcat(graph[4], "  *");
            strcat(graph[5], "  *");
            strcat(graph[6], "  *");
        }
        else if (latestspeed >= 640)
        {
            strcat(graph[0], "   ");
            strcat(graph[1], "   ");
            strcat(graph[2], "   ");
            strcat(graph[3], "   ");
            strcat(graph[4], "  *");
            strcat(graph[5], "  *");
            strcat(graph[6], "  *");
        }
        else if (latestspeed >= 320)
        {
            strcat(graph[0], "   ");
            strcat(graph[1], "   ");
            strcat(graph[2], "   ");
            strcat(graph[3], "   ");
            strcat(graph[4], "   ");
            strcat(graph[5], "  *");
            strcat(graph[6], "  *");
        }
        else if (latestspeed > 0)
        {
            strcat(graph[0], "   ");
            strcat(graph[1], "   ");
            strcat(graph[2], "   ");
            strcat(graph[3], "   ");
            strcat(graph[4], "   ");
            strcat(graph[5], "   ");
            strcat(graph[6], "  *");
        }
        else //speed is 0
        {
            strcat(graph[0], "   ");
            strcat(graph[1], "   ");
            strcat(graph[2], "   ");
            strcat(graph[3], "   ");
            strcat(graph[4], "   ");
            strcat(graph[5], "   ");
            strcat(graph[6], "   ");
        }
    }

    //build string to print
    int i;
    for (i = 0; i < BUFLEN; i++)
        strcat(graphstring, graph[i]);

    return graphstring;
}

netsnmp_pdu *makepdu(char myoid[], int getornextorset)
{
    netsnmp_pdu *pdu;
    oid anOID[MAX_OID_LEN];
    size_t anOID_len;
    anOID_len = MAX_OID_LEN;
    get_node(myoid, anOID, &anOID_len);

    if (getornextorset == GET)
        pdu = snmp_pdu_create(SNMP_MSG_GET);
    else if (getornextorset == GETNEXT)
       pdu = snmp_pdu_create(SNMP_MSG_GETNEXT); 
    else //set
    {
       pdu = snmp_pdu_create(SNMP_MSG_SET); 
       char *ivalues = "1"; //update every 1 second
       snmp_add_var(pdu, anOID, anOID_len, 'i', ivalues);
    }

    if (getornextorset == GET || getornextorset == GETNEXT)    
        snmp_add_null_var(pdu, anOID, anOID_len);
    return pdu;
}

char **findAllAddrs(netsnmp_session *ss, 
    int **alladdrs[BUFLEN][BUFLEN], int icounter)
{
    netsnmp_pdu *response;
    netsnmp_variable_list *vars;
    int status;
    int k;
    char *ipaddition[BUFLEN];
    char *ipoid[BUFLEN];
    sprintf(ipoid, "ipAdEntAddr.");

    //grabbing all interface ips loop -------------------------
    for (k = 0; k < icounter; k++)
    {
        netsnmp_pdu *ippdu = makepdu(ipoid, GETNEXT);
        status = snmp_synch_response(ss, ippdu, &response);
        if (status == STAT_SUCCESS 
            && response->errstat == SNMP_ERR_NOERROR) 
        {
            vars = response->variables;
            u_char *ip = vars->val.string;
            char iptemp[BUFLEN];
            sprintf(ipaddition, "%d", ip[0]);
            strcat(ipaddition, ".");
            sprintf(iptemp, "%d", ip[1]);
            strcat(ipaddition, iptemp);
            strcat(ipaddition, ".");
            sprintf(iptemp, "%d", ip[2]);
            strcat(ipaddition, iptemp);
            strcat(ipaddition, ".");
            sprintf(iptemp, "%d", ip[3]);
            strcat(ipaddition, iptemp);
            strcat(alladdrs[k], ipaddition);
            //printf("%s\n", alladdrs[k]);
            sprintf(ipoid, "ipAdEntAddr.%s", ipaddition);
        }                  
    }
    return alladdrs;
}


