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
    Find ipNeighbors, (routers near you)
    Represent monitored data in graph.
    Make tables for interfaces and ipNeighbors.
    Analyze accuracy report for extra credit.
    Restructure whole thing to do monitoring for each interface to better match how spec words it?? YES, we do need this.
    Traffic includes upload as well as download, need opposites.
*/

netsnmp_pdu *makepdu(char myoid[], int getornext);
char **findAllAddrs(netsnmp_session *ss, int **alladdrs[BUFLEN][BUFLEN], int icounter);

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
    for (m = 0; m < icounter; m++) 
    {
        //specific to local loop
        if (strcmp(inameholder[m], "lo") == 0)
        { 
            strcpy(iipholder[m], "local loop");
            printf("%s is %d, local loop\n", inameholder[m], inumholder[m]);
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
                    printf("%s is %d at %s\n", inameholder[m], inumholder[m], alladdrs[j]);
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
                    printf("%s is %d with no ip\n", inameholder[m], inumholder[m]);
                    break;
                }
            }
        }
    }

    //get ip neighbors loop----------------------------
    for(m = 0; m < 1; m++)
    {
        char myoid[] = "";
    }


    //set agent to update more often (every 1 second):
    char setoid[] = ("nsCacheTimeout.1.3.6.1.2.1.2.2");
    netsnmp_pdu *setpdu = makepdu(setoid, SET);
    snmp_synch_response(ss, setpdu, &response);


    //MONITORING LOOP!----------------------------------
    for (m = 0; m < numsamples; m++)
    {
        //oid used in class example, octets are BYTES
        char inoid[] = "ifInOctets.3";
        char outoid[] = "ifOutOctets.3";

        //a brand new pdu is required for each.
        netsnmp_pdu *pdu = makepdu(inoid, GET);

        //Send the Request out.
        status = snmp_synch_response(ss, pdu, &response);

        //Process the response.
        if (status == STAT_SUCCESS 
            && response->errstat == SNMP_ERR_NOERROR) 
        {
            //SUCCESS: Print the result variables
            vars = response->variables;
            print_variable(vars->name, vars->name_length, vars);
        }

        //clean up
        if (response)
            snmp_free_pdu(response);

        //take a break
        sleep(secondsinterval);
    }

    snmp_close(ss);
    SOCK_CLEANUP;
    return (0);
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

char **findAllAddrs(netsnmp_session *ss, int **alladdrs[BUFLEN][BUFLEN], int icounter)
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

