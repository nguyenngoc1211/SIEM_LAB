# A1-T1190-01

Sends harmless HTTP requests to the existing local Nginx gateway, including a
SQLmap-style User-Agent. The expected primary detection is active ET SID
2008538. No SQL statement is executed and no external target is contacted.
The expected technique is `T1190`, taken directly from the active ET rule
metadata. The mapper result is evaluated independently against that value.
