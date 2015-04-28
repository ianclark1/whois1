<!---
	Name         : whois.cfc
	Author       : Paul Vernon, New Media Development Ltd (http://www.newmediadevelopment.net/)
	Created      : 09 Nov 2009
	Last Updated : 09 Nov 2009
	History      : Version 1
						Added basic whois query
						Added referral check and re-submission of whois lookup (recursive)

	Purpose		 : To create a CFX_WHOIS replacement.

	Example		 :

	<cfset whois = createObject("component", "whois").init()>
	<cfset result = whois.lookup("whois.internic.net", "newmediadev.net")>
	<cfdump var="#result#">

--->

<cfcomponent name="whois" displayName="WHOIS" output="false"
		hint="Provides WHOIS functions.">

	<cffunction name="init" type="public" returntype="Whois" output="false"
			hint="Constructor function.">

		<cfreturn this>
	</cffunction>

	<cffunction name="stripComments" type="private" returntype="string" output="false"
			hint="Removes all comments from the returned result">
		<cfargument name="result" type="string" required="true" hint="Looks for a variety of referral instructions.">

		<cfset var parsedResult = ReReplaceNoCase(arguments.result, "\-\-[\w\W ]*?((\r)?\n)", "", "ALL")>
		<cfset parsedResult = ReReplaceNoCase(parsedResult, "%[\w\W ]*?((\r)?\n)", "", "ALL")>

		<cfreturn Trim(parsedResult)>
	</cffunction>

	<cffunction name="deriveStatus" type="private" returntype="string" output="false"
			hint="Attempts to derive the status of the domain">
		<cfargument name="whoisResponse" type="string" required="true">

		<cfif REFindNoCase("(redemptionperiod)", arguments.whoisResponse)>
			<cfreturn "REDEMPTION">
		</cfif>
		<cfif REFindNoCase("(locked|registry-hold|registrar-hold|registrar-lock|clientTransferProhibited|clientUpdateProhibited)", arguments.whoisResponse)>
			<cfreturn "LOCKED">
		</cfif>
		<cfif REFindNoCase("(pendingrestore)", arguments.whoisResponse)>
			<cfreturn "PENDINGRESTORE">
		</cfif>
		<cfif REFindNoCase("(pendingdelete)", arguments.whoisResponse)>
			<cfreturn "PENDINGDELETE">
		</cfif>
		<cfif REFindNoCase("(detagged)", arguments.whoisResponse)>
			<cfreturn "DETAGGED">
		</cfif>
		<cfif REFindNoCase("(not registered|no match|no entries|not found|no data found|status:[\s]*free|status:[\s]*avail|status:[\s]*available)", arguments.whoisResponse)>
			<cfreturn "AVAILABLE">
		</cfif>
		<cfif REFindNoCase("(domain name:|domain:|domain name\.\.\.|domain name :|registrant:|registered|status:[\s]*active)", arguments.whoisResponse)>
			<cfreturn "UNAVAILABLE">
		</cfif>
		<cfif arguments.WhoisResponse NEQ "">
			<cfreturn "UNDETERMINED">
		</cfif>

		<cfreturn "FAILED">
	</cffunction>

	<cffunction name="WhoisEx" access="private" returntype="string" output="false"
			hint="Performs a whois call.">
		<cfargument name="host" type="string" required="true" hint="The whois server we want to talk to.">
		<cfargument name="domain" type="string" required="true" hint="The domain we want the whois info for.">
		<cfargument name="port" type="numeric" required="false" default="43" hint="The port to connect to." >

		<cfset var socket = createObject("component", "socket").init(arguments.host, arguments.port)>
		<cfset var result = "">

		<cftry>
				<cfif socket.connect()>
					<cfset socket.write(arguments.domain)>
					<!---
						the server side socket is meant to close when it has sent the data however,
						detecting the servers closed state doesn't seem to work...

						Adding a half second delay before retrieving the data from the socket seems to get around issues of
						partial data being on the socket and faulty detection of the end of data.

						Whois protocol is pants!
					--->
					<cfset sleep(500)>
					<cfset result = socket.read()>
					<cfset socket.close()>
				</cfif>
			<cfcatch>
				<cfif not socket.isClosed()>
					<cfset socket.close()>
				</cfif>
			</cfcatch>
		</cftry>

		<cfreturn result>
	</cffunction>

	<cffunction name="getReferralServer" access="private" returntype="string" output="false"
			hint="Runs a few RegEx over the results to check for a referral.">
		<cfargument name="result" type="string" required="true" hint="Looks for a variety of referral instructions.">

		<cfset var parsedresult = stripComments(arguments.result)>
		<cfset var whoisServer = REFindNoCase("[\s]*whois server:[\s]+([a-z0-9\-\.]*)", parsedresult, 1, true)>

		<cfif ArrayLen(whoisServer.Pos) IS 0>
			<cfset whoisServer = REFindNoCase("[\s]*referto:[\s]+([a-z0-9\-\.]*)", parsedresult, 1, true)>
		</cfif>

		<cfif ArrayLen(whoisServer.Pos) IS 0>
			<cfset whoisServer = REFindNoCase("[\s]*referralserver: whois://[\s]+([a-z0-9\-\.]*)", parsedresult, 1, true)>
		</cfif>

		<cfif ArrayLen(whoisServer.Pos) IS 0>
			<cfset whoisServer = REFindNoCase("[\s]*referralserver: rwhois://[\s]+([a-z0-9\-\.]*)", parsedresult, 1, true)>
		</cfif>

		<cfif ArrayLen(whoisServer.Pos) IS 2>
			<cfreturn Mid(parsedresult, whoisServer.Pos[2], whoisServer.Len[2])>
		<cfelse>
			<cfreturn "">
		</cfif>
	</cffunction>

	<cffunction name="LookupEx" access="private" returntype="string" output="false"
			hint="Perform the whois lookup and parse the results until the full record is returned.">
		<cfargument name="host" type="string" required="true" hint="The whois server we want to talk to.">
		<cfargument name="domain" type="string" required="true" hint="The domain we want the whois info for.">
		<cfargument name="port" type="numeric" required="false" default="43" hint="The port to connect to." >

		<cfset var result = WhoisEx(argumentCollection=arguments)>
		<cfset var whoisServer = getReferralServer(result)>

		<cfif whoisServer NEQ "">
			<cfset arguments.host = whoisServer>
			<!--- recursively lookup the whois record --->
			<cfset result = LookupEx(argumentCollection=arguments)>
		</cfif>

		<cfreturn result>
	</cffunction>

	<cffunction name="Lookup" access="public" returntype="struct" output="false"
			hint="Call the LookupEx function and always get the last whois server response">
		<cfargument name="host" type="string" required="true" hint="The whois server we want to talk to.">
		<cfargument name="domain" type="string" required="true" hint="The domain we want the whois info for.">
		<cfargument name="port" type="numeric" required="false" default="43" hint="The port to connect to." >

		<cfset var result = StructNew()>
		<cfset var lookupresult = LookupEx(argumentCollection=arguments)>
		<cfset var parsedresult = "">

		<cfset parsedresult = stripComments(lookupresult)>
		<cfif parsedresult IS "">
			<cfset parsedresult = lookupresult>
		</cfif>

		<cfset StructInsert(result, "Response", lookupresult)>
		<cfset StructInsert(result, "Result", deriveStatus(parsedResult))>

		<cfreturn result>
	</cffunction>

</cfcomponent>

<!---

A list of some more common TLD domains and their respective whois servers.

.co.uk	whois.nic.uk
.eu.com	whois.centralnic.net
.gb.com	whois.centralnic.net
.ltd.uk	whois.nic.uk
.me.uk	whois.nic.uk
.org.uk	whois.nic.uk
.uk.com	whois.centralnic.net
.uk.net	whois.centralnic.net
.us.com	whois.centralnic.net
.net.uk	whois.nic.uk
.plc.uk	whois.nic.uk
.sch.uk	whois.nic.uk
.gb.net	whois.centralnic.com
.com	whois.internic.net
.net	whois.internic.net
.org	whois.pir.org
.info	whois.afilias.net
.ca		whois.cira.ca
.be		whois.dns.be
.biz	whois.biz

--->