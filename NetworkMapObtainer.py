import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import json
import urllib3
import time





urllib3.disable_warnings()

"""
Api Reference
For getting Virtual Servers: https://F5Ip/mgmt/tm/ltm/virtual/?expandSubcollections=true
For getting pools with members: https://F5Ip/mgmt/tm/ltm/pool/?expandSubcollections=true

For getting policies with actions: https://F5Ip/mgmt/tm/ltm/policy/?expandSubcollections=true 
For getting irules with contents: https://F5Ip/mgmt/tm/ltm/rule
"""


class iRule():
    def __init__(self,name):
        self.name = name
        self.partition = "unset"
        self.tclText = "unset"
        #This list includes pool names
        self.poolsInLines = []
        #This list includes pool objects
        self.pools = []

        

class PolicyActionReference():
    def __init__(self):
        self.forward = False
        self.poolName = "unset"
        self.poolPartition = "unset"
        self.pool = None


class PolicyRule():
    def __init__(self,name):
        self.name = name
        self.actionReferences = []
        self.conditionReferences = []


class Policy():
    def __init__(self,name):
        self.name = name
        self.partition = "unset"
        self.status = "unset"
        self.rules = []






class PoolMember():
    def __init__(self, name):
        self.name = name
        self.ipAddress = "unset"
        self.port = "unset"
        self.adminState = "unset"
        self.operationalState = "unset"
        self.dataCenter = "unset"
        self.dataCenterZone = "unset"


class Pool():
    def __init__(self,name):
        self.name = name
        self.partition = "unset"
        self.loadBalancingMode = "unset"
        self.members = []
        # A pool consumed by chosen as a default pool, set destination in a policy or forwardes in an iRule
        self.consumedBy = "unset"


class VirtualServer():
    def __init__(self,name):
        self.name = name
        self.partition = "unset"
        self.sourceIp = "unset"
        self.destinationIp = "unset"
        self.destinationPort = "unset"
        self.defaultPoolName = "unset"
        self.defaultPoolPartition = "unset"
        self.defaultPool = None
        self.pools = []
        self.policies = []
        self.iRules = []
        """
        A list with members of dictionary; {"rulePartition":Partition, "ruleName":RuleName}
        """
        self.iRulesInfo = []
        """
        A list with members of dictionary; {"policyPartition":Partition, "policyName":RuleName}
        """
        self.policiesInfo = []
        

class F5_LoadBalancer():
    def __init__(self, managementIP, username, password):
        '''
        Constructor
        '''
        self.managementIp = managementIP
        self.username = username
        self.password = password
        self.dataCenter = "unset"
        self.zone = "unset"
        self.authentication = False
        self.checkForAuthentication()
        self.virtualServers = []
        self.pools = []
        self.policies = []
        self.iRules = []
        self.errors = []

    def checkForAuthentication(self):
        '''
        Checking username and password are valid, and Object can authenticate to F5
        '''
        urlForCheck =  "https://" + self.managementIp + "/mgmt/tm/ltm/"
        try:
            r = requests.get(urlForCheck, auth=(self.username, self.password), verify = False)
            json_F5 = json.loads(r.text)
            self.authentication = True
            print("Authentication Succesfull")
        except:
            print("Authentication Failed")
        finally:
            pass

    def getVirtualServers(self,virtualServerSubCollectionsExpand = False):
        '''
        Getting virtual servers of F5, parsing to obtain
        '''
        if self.authentication:
            if not virtualServerSubCollectionsExpand:
                print("Subcollections expand mode is NOT used to obtain virtual server information...")
                urlForVirtualServers =  "https://" + self.managementIp + "/mgmt/tm/ltm/virtual"
                r = requests.get(urlForVirtualServers, auth=(self.username, self.password), verify = False,timeout = 200)
                json_F5 = json.loads(r.text)
                for vs in json_F5["items"]:
                    try:
                        tempVirtualServer = VirtualServer(vs["name"])
                        tempVirtualServer.partition = vs["partition"]
                        tempVirtualServer.sourceIp = vs["source"]
                        tempVirtualServer.destinationIp = vs["destination"].split("/")[2].split(":")[0]
                        tempVirtualServer.destinationPort = vs["destination"].split("/")[2].split(":")[1]
                        if "pool" in vs:
                            #if a pool is not configured by a iApp template, path will be like /partition/pool
                            if len(vs["pool"].split('/')) == 3:
                                tempVirtualServer.defaultPoolName = vs["pool"].split('/')[2]
                                tempVirtualServer.defaultPoolPartition = vs["pool"].split('/')[1]
                            #if a pool is configured by a iApp template, path will be like /partition/application/pool
                            if len(vs["pool"].split('/')) == 4:
                                tempVirtualServer.defaultPoolName = vs["pool"].split('/')[3]
                                tempVirtualServer.defaultPoolPartition = vs["pool"].split('/')[1]

                        #Obtaining irules in virtuals server
                        if "rules" in vs:
                            for rule in vs["rules"]:
                                rulePartition = rule.split('/')[1]
                                ruleName = rule.split('/')[2]
                                tempVirtualServer.iRulesInfo.append({"rulePartition":rulePartition, "ruleName":ruleName})
                        #Obtaining Policies used on virtual server
                        try:
                            urlForVirtualServerPolicies =  "https://" + self.managementIp + "/mgmt/tm/ltm/virtual/~"+tempVirtualServer.partition + "~" + tempVirtualServer.name + "/policies"
                            r = requests.get(urlForVirtualServerPolicies, auth=(self.username, self.password), verify = False,timeout = 200)
                            policyJson_F5 = json.loads(r.text)
                            for policyItem in policyJson_F5["items"]:
                                tempVirtualServer.policiesInfo.append({"policyPartition":policyItem["partition"], "policyName":policyItem["name"]})
                        except Exception as exc:
                            print("Failed to obtain virtual server policies json, Error for " + tempVirtualServer.name)
                            self.errors.append("Virtual Server Policy Data Obtaining Error: Failed to obtain virtual server policies json for virtual server " + tempVirtualServer.name)
                            print(exc)
                        
                        self.virtualServers.append(tempVirtualServer)

                        del tempVirtualServer
                    except Exception as exc:
                        print("Failed to parse virtual server json, Error: ")
                        print(exc)
            else:
                print("Subcollections expand mode is used to obtain virtual server information...")
                urlForVirtualServers =  "https://" + self.managementIp + "/mgmt/tm/ltm/virtual/?expandSubcollections=true"
                r = requests.get(urlForVirtualServers, auth=(self.username, self.password), verify = False,timeout = 200)
                json_F5 = json.loads(r.text)
                for vs in json_F5["items"]:
                    try:
                        tempVirtualServer = VirtualServer(vs["name"])
                        tempVirtualServer.partition = vs["partition"]
                        tempVirtualServer.sourceIp = vs["source"]
                        tempVirtualServer.destinationIp = vs["destination"].split("/")[2].split(":")[0]
                        tempVirtualServer.destinationPort = vs["destination"].split("/")[2].split(":")[1]
                        if "pool" in vs:
                            if len(vs["pool"].split('/')) == 3:
                                tempVirtualServer.defaultPoolName = vs["pool"].split('/')[2]
                                tempVirtualServer.defaultPoolPartition = vs["pool"].split('/')[1]
                            if len(vs["pool"].split('/')) == 4:
                                tempVirtualServer.defaultPoolName = vs["pool"].split('/')[3]
                                tempVirtualServer.defaultPoolPartition = vs["pool"].split('/')[1]

                        #Obtaining irules in virtuals server
                        if "rules" in vs:
                            for rule in vs["rules"]:
                                rulePartition = rule.split('/')[1]
                                ruleName = rule.split('/')[2]
                                tempVirtualServer.iRulesInfo.append({"rulePartition":rulePartition, "ruleName":ruleName})
                        #Obtaining Policies used on virtual server
                        try:
                            if "policiesReference" in vs:
                                if "items" in vs["policiesReference"]:
                                    for item in vs["policiesReference"]["items"]:
                                        tempVirtualServer.policiesInfo.append({"policyPartition":item["partition"], "policyName":item["name"]})
                        except Exception as exc:
                            print("Failed to obtain virtual server policies json, Error for " + tempVirtualServer.name)
                            self.errors.append("Virtual Server Policy Data Obtaining Error: Failed to obtain virtual server policies json for virtual server " + tempVirtualServer.name)
                            print(exc)
                        self.virtualServers.append(tempVirtualServer)
                        del tempVirtualServer
                    except Exception as exc:
                        print("Failed to parse virtual server json, Error: ")
                        print(exc)

    def getPools(self):
        '''
        Getting pools with members
        '''
        if self.authentication:
            try:
                urlForPools = "https://"+self.managementIp+"/mgmt/tm/ltm/pool/?expandSubcollections=true"
                r = requests.get(urlForPools, auth=(self.username, self.password), verify = False, timeout=200)
                json_F5 = json.loads(r.text)
                for pool in json_F5["items"]:
                    try:
                        tempPool = Pool(pool["name"])
                        tempPool.partition = pool["partition"]
                        tempPool.loadBalancingMode = pool["loadBalancingMode"]
                        if "membersReference" in pool:
                            if "items" in pool["membersReference"]:
                                for member in pool["membersReference"]["items"]:
                                    tempMember = PoolMember(member["name"])
                                    tempMember.partition = member["partition"]
                                    tempMember.ipAddress = member["address"]
                                    if '%' in member["address"]:
                                        tempMember.ipAddress = member["address"].split("%")[0]
                                    tempMember.port = member["name"].split(":")[1]
                                    tempMember.adminState = member["state"]
                                    tempMember.operationalState = member["session"]
                                    tempPool.members.append(tempMember)
                                    del tempMember
                        self.pools.append(tempPool)
                    except Exception as exc:
                        print("Failed to parse pools  json, Error: ")
                        print(exc)
            except Exception as exc:
                print("HTTP GET Error: Failed to obtain pools from F5 with ip " + self.managementIp + ".Error is")
                self.errors.append("HTTP GET Error: Failed to obtain pools from F5 with ip " + self.managementIp)
                print(exc)
        else:
            print("Authentication Error: Failed to obtain pools data from F5 with ip " + self.managementIp)
            self.errors.append("Authentication Error: Failed to obtain pools data from F5 with ip " + self.managementIp)

    def getPolicies(self):
        '''
        Getting policies with actions
        With this function, condition references are not collected due to aim of this software
        '''
        if self.authentication:
            try:
                urlForPolicies = "https://"+self.managementIp+"/mgmt/tm/ltm/policy/?expandSubcollections=true"
                r = requests.get(urlForPolicies, auth=(self.username, self.password), verify = False,timeout=200)
                json_F5 = json.loads(r.text)
                for policy in json_F5["items"]:
                    try:
                        tempPolicy = Policy(policy["name"])
                        tempPolicy.partition = policy["partition"]
                        tempPolicy.status = policy["status"]
                        if "rulesReference" in policy:
                            if "items" in policy["rulesReference"]:
                                for rule in policy["rulesReference"]["items"]:
                                    tempPolicyRule = PolicyRule(rule["name"])
                                    if "actionsReference" in rule:
                                        if "items" in rule["actionsReference"]:
                                            for action in rule["actionsReference"]["items"]:
                                                tempActionReference = PolicyActionReference()
                                                """
                                                A Forward action can be applied not only to a pool, this may be a pool or virtual, etc.
                                                """
                                                if ("forward" in action) and ("pool" in action):
                                                    tempActionReference.forward = action["forward"]
                                                    tempActionReference.poolName = action["pool"].split("/")[2]
                                                    tempActionReference.poolPartition = action["pool"].split("/")[1]
                                                    tempPolicyRule.actionReferences.append(tempActionReference)
                                                    del tempActionReference
                                    tempPolicy.rules.append(tempPolicyRule)
                                    del tempPolicyRule
                        self.policies.append(tempPolicy)
                        del tempPolicy
                    except Exception as exc:
                        print("Failed to parse policy json, Error on " + policy["name"])
                        print(exc)
            except Exception as exc:
                print("HTTP GET Error: Failed to obtain policies from F5 with ip " + self.managementIp + ".Error is")
                self.errors.append("HTTP GET Error: Failed to obtain policies from F5 with ip " + self.managementIp)
                print(exc)
        else:
            print("Authentication Error: Failed to obtain policy data from F5 with ip " + self.managementIp)
            self.errors.append("Authentication Error: Failed to obtain policy data from F5 with ip " + self.managementIp)

    def getI_Rules(self):
        '''
        Getting irules including tcl scripts
        With this function, lines including 'pool' keyword are obtained
        '''
        
        if self.authentication:
            try:
                urlForiRules= "https://"+self.managementIp+"/mgmt/tm/ltm/rule"
                r = requests.get(urlForiRules, auth=(self.username, self.password), verify = False)
                json_F5 = json.loads(r.text)
                for rule in json_F5["items"]:
                    try:
                        tempRule = iRule(rule["name"])
                        tempRule.partition = rule["partition"]
                        """
                        Key value 'apiAnonymous' won't exist if an irule has no code,
                        """
                        if "apiAnonymous" in rule:
                            tempRule.tclText = rule["apiAnonymous"]
                            tempTclLines = tempRule.tclText.splitlines()
                            for line in tempTclLines:
                                """
                                According to document at link https://clouddocs.f5.com/api/irules/pool.html
                                "pool" keyword usage in F5 iRule has two ways
                                1. pool PoolName
                                2. pool PoolName member MemberIp MemberPort

                                As a summary, 
                                - In both of the usage, this line has to start with a keyword "pool"
                                - Word count can be 2 or 5, in case of 5, 3th word has to be "member"
                                """
                                if "pool" in line:
                                    words = line.split()
                                    if len(words) == 2 and words[0] == "pool":
                                        tempRule.poolsInLines.append(line.split()[1])
                                    if len(words) == 5 and words[0] == "pool":
                                            if words[2] == "member":
                                                tempRule.poolsInLines.append(line.split()[1])
                        self.iRules.append(tempRule)
                        del tempRule
                    except Exception as exc:
                        print("Failed to parse irule json, Error on irule " +  rule["name"])
                        self.errors.append("Parsing Error: Failed to parse irule json, Error on irule " +  rule["name"])
                        print(exc)
            except Exception as exc:
                print("HTTP GET Error: Failed to obtain irules from F5 with ip " + self.managementIp + ".Error is")
                self.errors.append("HTTP GET Error: Failed to obtain irules from F5 with ip " + self.managementIp)
                print(exc)
        else:
            print("Authentication Error: Failed to obtain irule data from F5 with ip " + self.managementIp)
            self.errors.append("Authentication Error: Failed to obtain irule data from F5 with ip " + self.managementIp)

    def discovery(self, virtualServerSubCollectionsExpand = False):
        
        print("Collecting pools from " + self.managementIp)
        self.getPools()
        print("Collecting policies from " + self.managementIp)
        self.getPolicies()
        print("Collecting irules from " + self.managementIp)
        self.getI_Rules()
        print("Collecting virtual servers from " + self.managementIp)
        self.getVirtualServers(virtualServerSubCollectionsExpand=virtualServerSubCollectionsExpand)

        print("Matching pools to policy is starting...")
        for policy in self.policies:
            for rule in policy.rules:
                for action in rule.actionReferences:
                    poolFound = False
                    for pool in self.pools:
                        if pool.partition == action.poolPartition and pool.name == action.poolName:
                            action.pool = pool
                            poolFound = True
                    if not poolFound:
                        self.errors.append("Pool can not be found; Forwarded pool with name "+ action.poolName +" in rule " + rule.name + " of " + policy.name + " policy on partition : " + policy.partition)
        print("Matching pools to irules is starting...")
        for irule in self.iRules:
            for poolName in irule.poolsInLines:
                poolFound = False
                for pool in self.pools:
                    if irule.partition == pool.partition and poolName == pool.name:
                        irule.pools.append(pool)
                        poolFound = True
                if not poolFound:
                    self.errors.append("Pool can not be found; Forwarded pool with name "+ poolName +" in irule " + irule.name + " of " + irule.partition)
        
        print("Matching default pools of Virtual Servers is starting...")
        for vs in self.virtualServers:
            if vs.defaultPoolName != "unset" and vs.defaultPoolPartition != "unset":
                try:
                    poolFound = False
                    for pool in self.pools:
                        if vs.defaultPoolName == pool.name and vs.defaultPoolPartition == pool.partition:
                            vs.defaultPool = pool
                            poolFound = True
                    if not poolFound:
                        self.errors.append("Pool can not be found; default pool of "+ vs.name +" is " + vs.defaultPool + " on " + vs.defaultPoolPartition + " partition")
                        
                except Exception as exc:
                    print("Failed to match pool information for virtual server " + vs.name + " on partition "+ vs.partition + " pool name " + vs.defaultPoolName)
                    print(exc)
        print("Matching irules and policies to Virtual Servers is starting...")
        for vs in self.virtualServers:
            for iRuleInfo in vs.iRulesInfo:
                ruleFound = False
                for iRule in self.iRules:
                    if iRule.name == iRuleInfo["ruleName"] and iRule.partition == iRuleInfo["rulePartition"]:
                        vs.iRules.append(iRule)
                        ruleFound = True
                if not ruleFound:
                    self.errors.append("iRule missing: iRule with name " + iRuleInfo["ruleName"] + " on partition " + iRuleInfo["rulePartition"]/
                    + " can not be found for virtual server " + vs.name + " on partition " + vs.partition)
            
            for policyInfo in vs.policiesInfo:
                policyFound = False
                for policy in self.policies:
                    if policy.name == policyInfo["policyName"] and policy.partition == policyInfo["policyPartition"]:
                        vs.policies.append(policy)



    def buildJsonNetworkMap(self, nameOfFile = "networkMap.json"):
        returnedJson = {"VirtualServers": []}
        for virtualServer in self.virtualServers:
            tempVirtualServerDict = {"name": virtualServer.name,"partition": virtualServer.partition, "pools": []}
            #Adding default virtual server pool to json
            if virtualServer.defaultPool:
                tempPoolDict = {"poolOrigin": "virtualServerDefaultPool","name": virtualServer.defaultPool.name,"partition": virtualServer.defaultPool.partition, "loadBalancingMethod": virtualServer.defaultPool.loadBalancingMode, "members":[]}
                for member in virtualServer.defaultPool.members:
                    tempPoolDict["members"].append({"ipAddress": member.ipAddress, "memberPort": member.port,"adminState": member.adminState,"operationalState": member.operationalState})
                tempVirtualServerDict["pools"].append(tempPoolDict)
            
            for iRule in virtualServer.iRules:
                if len(iRule.pools):
                    for pool in iRule.pools:
                        tempPoolDict = {"poolOrigin": "iRule", "iRuleName": iRule.name, "iRulePartition": iRule.partition,"name": pool.name,"partition": pool.partition, "loadBalancingMethod": pool.loadBalancingMode, "members":[]}
                        for member in pool.members:
                            tempPoolDict["members"].append({"ipAddress": member.ipAddress, "memberPort": member.port,"adminState": member.adminState,"operationalState": member.operationalState})
                        tempVirtualServerDict["pools"].append(tempPoolDict)
            for policy in virtualServer.policies:
                for rule in policy.rules:
                    for action in rule.actionReferences:
                        if action.forward:
                            if action.pool:
                                tempPoolDict = {"poolOrigin": "policy", "policyName": policy.name, "policyPartition": policy.partition,"ruleName": rule.name,"name": action.pool.name, "partition": action.pool.partition, "loadBalancingMethod": action.pool.loadBalancingMode, "members":[]}
                                for member in action.pool.members:
                                    tempPoolDict["members"].append({"ipAddress": member.ipAddress, "memberPort": member.port,"adminState": member.adminState,"operationalState": member.operationalState})
                                tempVirtualServerDict["pools"].append(tempPoolDict)
            returnedJson["VirtualServers"].append(tempVirtualServerDict)
            del tempVirtualServerDict
        jsonToWrite = json.dumps(returnedJson)
        fileWriter(nameOfFile, jsonToWrite)

def fileWriter(where,what):
    Filer = open(where,"w")
    Filer.write(what)
    Filer.close()

if __name__ == "__main__":
    startTime = int(time.time())
    sampleF5 = F5_LoadBalancer("F5_ManagementIpAddress","Username","Password")
    sampleF5.discovery(virtualServerSubCollectionsExpand=True)
    sampleF5.buildJsonNetworkMap()

    
    for vs in sampleF5.virtualServers:
        print(vs.name + " partition " + vs.partition)
        if vs.defaultPool:
            print("Virtual Server default pool :" + vs.defaultPoolName)
            for member in vs.defaultPool.members:
                print("\t" + member.ipAddress  +"\t" + member.port + "\tadmin state:"  + member.adminState + "\toperational state:" + member.operationalState)
        for iRule in vs.iRules:
            if len(iRule.pools):
                print("\t\t These are pools forwarded by irule " + iRule.name)
                for pool in iRule.pools:
                    print("\t\t\tPool name:" + pool.name)
                    for member in pool.members:
                        print("\t\t\t" + member.ipAddress  +"\t" + member.port + "\tadmin state:"  + member.adminState + "\toperational state:" + member.operationalState)

        for policy in vs.policies:
            print("Policy Name: ")
            for rule in policy.rules:
                print("\tRule name: \t" + rule.name)
                for action in rule.actionReferences:
                    if action.forward:
                        print("\t\tForward to pool:\t"+ action.poolName + " on partition of " + action.poolPartition)
                        if action.pool:
                            for member in action.pool.members:
                                print("\t\t\t" + member.ipAddress  +"\t" + member.port + "\tadmin state:"  + member.adminState + "\toperational state:" + member.operationalState)

   
    print("Errors for F5 with ip " + sampleF5.managementIp)
    for error in sampleF5.errors:
        print(error)
    print("Total time is consumed: " + str(int(time.time())-startTime))
