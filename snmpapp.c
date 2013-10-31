#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <string.h>
#include <unistd.h>
#define SECONDSTOMONITOR 10

/*
 Authors: Matthew Somers and Erik Holden for CS166.
 Line 77 is the most important one here so far.
 Based on the example from:
 http://www.net-snmp.org/wiki/index.php/TUT:Simple_Application
*/

/*
    TODO:
    Set up arguments from spec.
    Find ipNeighbors, whatever that means.
    Find a way to refresh monitoring data faster (different oid?).
    Represent monitored data in graph.
    Make tables for interfaces and ipNeighbors.
    Analyze accuracy report for extra credit.
*/

netsnmp_pdu *makepdu(char myoid[]);

int main(int argc, char ** argv)
{
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
    session.peername = strdup("localhost");

    
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

    //get interfaces loop-------------------------------
    //goes until it finds 9 or fails finding ifDescrs (interfaces)
    for (icounter = '1'; icounter <= '9'; icounter++)
    {
        char myoid[] = "ifDescr. ";
        myoid[8] = icounter;
        netsnmp_pdu *pdu = makepdu(myoid);

        status = snmp_synch_response(ss, pdu, &response);
        if (status == STAT_SUCCESS && response->errstat == SNMP_ERR_NOERROR) 
        {
            for(vars = response->variables; vars; vars = vars->next_variable)
            print_variable(vars->name, vars->name_length, vars);
        }
        else
        {
            if (response)
                snmp_free_pdu(response);

            break; //IMPORTANT escape conditions
        }
        if (response)
            snmp_free_pdu(response);
    }

    //get ip neighbors loop----------------------------
    for(i = 0; i < 1; i++)
    {
        char myoid[] = "";
    }

    //MONITORING LOOP!----------------------------------
    for (i = 0; i < SECONDSTOMONITOR; i++)
    {
        //different choices to monitor:
        char myoid[] = "ifInUcastPkts.3";
        //char myoid[] = "ifOutUcastPkts.3";
        //char myoid[] = "ifOutOctets.3";
        //char myoid[] = "ifInOctets.3";

        //a brand new pdu is required for each get
        netsnmp_pdu *pdu = makepdu(myoid);

        //Send the Request out.
        status = snmp_synch_response(ss, pdu, &response);

        //Process the response.
        if (status == STAT_SUCCESS && response->errstat == SNMP_ERR_NOERROR) 
        {
            //SUCCESS: Print the result variables
            for(vars = response->variables; vars; vars = vars->next_variable)
            print_variable(vars->name, vars->name_length, vars);
        }

        //clean up
        if (response)
            snmp_free_pdu(response);

        //take 1 second break
        sleep(1);
    }

    snmp_close(ss);
    SOCK_CLEANUP;
    return (0);
}


netsnmp_pdu *makepdu(char myoid[])
{
    netsnmp_pdu *pdu;
    pdu = snmp_pdu_create(SNMP_MSG_GET);
    oid anOID[MAX_OID_LEN];
    size_t anOID_len;
    anOID_len = MAX_OID_LEN;

    get_node(myoid, anOID, &anOID_len);

    snmp_add_null_var(pdu, anOID, anOID_len);
    return pdu;

}
