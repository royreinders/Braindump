---
title: "Bloodhound queries"
date: 2020-07-17T20:59:33+02:00
draft: false
---
#### Useful Bloodhound queries
most taken from: https://twitter.com/n00py1/status/1508868743451090944
Mgeeky's awesome list of queries: https://github.com/mgeeky/Penetration-Testing-Tools/blob/master/red-teaming/bloodhound/Handy-BloodHound-Cypher-Queries.md

##### Setting a user as owned

```MATCH (n {name:'<NAME@DOMAIN.COM>'}) SET n.owned=true;```


##### Set groups that have admin count set as High Value

```MATCH p = (g:Group {admincount: True}) WHERE NOT EXISTS(g.highvalue) OR g.highvalue = False RETURN g```

##### Find users that have local admin rights, filtering out users with admincount

```MATCH p=(n:Group)-[:AdminTo*1..]->(m:Computer) WHERE NOT n.admincount RETURN p```

##### Mark computers that can perform constrained deligation as high value

```MATCH (c1:Computer)-[:MemberOf*1..]->(g:Group) WHERE g.objectid ENDS WITH '-516' WITH COLLECT(http://c1.name) AS domainControllers MATCH (c2:Computer {unconstraineddelegation:true}) WHERE NOT http://c2.name IN domainControllers RETURN c2```

##### Mark objects with inbound control over the domain high value

```MATCH p=shortestPath((n)-[r1:MemberOf|AllExtendedRights|GenericAll|GenericWrite|WriteDacl|WriteOwner|Owns*1..]->(u:Domain {name: "http://DOMAIN.COM"})) WHERE NOT http://n.name="http://DOMAIN.COM" RETURN p```

##### Mark groups that can reset passwords as high value

```MATCH p=(m:Group)-[r:ForceChangePassword]->(n:User) RETURN m```

##### Shortest path to high value targets

```MATCH p=shortestPath((g {owned:true})-[*1..]->(n {highvalue:true})) WHERE g<>n return p```

##### Kerberoastable account to high value

```MATCH p=shortestPath((n:User {hasspn:true})-[*1..]->(m:Group {highvalue:true})) RETURN p```

##### Find out if your user can do anything at all

```MATCH p = (g:User {owned: True})-[r]->(n) WHERE r.isacl=true RETURN p```
```MATCH p = (g1:User {owned: True})-[r1:MemberOf*1..]->(g2:Group)-[r2]->(n) WHERE r2.isacl=true RETURN p```

***


