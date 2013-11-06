#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <string.h>
#include <unistd.h>

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

/*
    IP-MIB::ipAdEntIfIndex.10.0.0.8 = INTEGER: 3
    IP-MIB::ipAdEntIfIndex.127.0.0.1 = INTEGER: 1

    These seem to be the only way to relate an ip and an interface. It will need some getnexts and annoying char array comparison gymnastics.
*/

netsnmp_pdu *makepdu(char myoid[], int getornext);

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
    int i;
    char icounter;

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

    int BUFLEN = 100;
    size_t *len = 100;
    u_char *buf[BUFLEN];
   size_t *outlen = 0;
    //get interfaces loop-------------------------------
    //goes until it finds 9 or fails finding ifDescrs (interfaces)
    for (icounter = '1'; icounter <= '9'; icounter++)
    {
        //most comments are in monitoring section
        //char myoid[] = "ifDescr. ";
        char myoid[] = "ifIndex. ";
        myoid[8] = icounter;
        netsnmp_pdu *pdu = makepdu(myoid, 0); //0 is get

        status = snmp_synch_response(ss, pdu, &response);
        if (status == STAT_SUCCESS 
            && response->errstat == SNMP_ERR_NOERROR) 
        {
            vars = response->variables;
            print_variable(vars->name, vars->name_length, vars);

            //sprint_realloc_integer(buf, len, outlen, 0, vars, NULL, NULL, NULL);
            
            printf("\n%li\n", *vars->val.integer);
        }
        

        else //failed finding next ifDescr
        {
            if (response)
                snmp_free_pdu(response);

            break; //IMPORTANT escape conditions
        }

        //find an interface's ip-----------------------
        char ipoid[100];
        if (icounter == '1')
            strncpy(ipoid, "ipAdEntAddr.10.0.0.8", sizeof(ipoid));
        else
        {

        }


        
        netsnmp_pdu *ippdu = makepdu(ipoid, 1); //getnext is 1
        status = snmp_synch_response(ss, ippdu, &response);
        if (status == STAT_SUCCESS 
            && response->errstat == SNMP_ERR_NOERROR) 
        {
            vars = response->variables;
            print_variable(vars->name, vars->name_length, vars);

            u_char *ip = vars->val.string;
            printf("%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]);
        }

        //strncpy(ipentry, vars->name, sizeof(ipentry));
        //printf("\n%s\n", ipentry);
        if (response)
        {
            snmp_free_pdu(response);
        }
    }

    //get ip neighbors loop----------------------------
    for(i = 0; i < 1; i++)
    {
        char myoid[] = "";
    }

    //MONITORING LOOP!----------------------------------
    for (i = 0; i < numsamples; i++)
    {
        //different choices to monitor:
        //char myoid[] = "ifInUcastPkts.3";
        //char myoid[] = "ifOutUcastPkts.3";
        //char myoid[] = "ifOutOctets.3";
        
        //one used in class example, octets are BYTES
        char myoid[] = "ifInOctets.3";

        //other potential good one
        //char myoid[] = "ipInDelivers.0";
        //char myoid[] = "ipInReceives.0";

        //a brand new pdu is required for each. Get is 0
        netsnmp_pdu *pdu = makepdu(myoid, 0);

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


netsnmp_pdu *makepdu(char myoid[], int getornext)
{
    netsnmp_pdu *pdu;

    if (getornext == 0)
        pdu = snmp_pdu_create(SNMP_MSG_GET);
    else
       pdu = snmp_pdu_create(SNMP_MSG_GETNEXT); 

    oid anOID[MAX_OID_LEN];
    size_t anOID_len;
    anOID_len = MAX_OID_LEN;

    get_node(myoid, anOID, &anOID_len);

    snmp_add_null_var(pdu, anOID, anOID_len);
    return pdu;

}
