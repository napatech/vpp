Napatech IPFIX flow record plugin    {#ntflowprobe_plugin_doc}
========================

## Introduction

This plugin generates ipfix flow records on interfaces which have the feature enabled.
It was developed to demonstrate hardware accelerated flow tracking in Napatech adapters.

## Sample configuration

ntflowprobe enable HundredGigabitEthernet2/0/0/0 HundredGigabitEthernet2/0/0/1 collector 192.168.1.3 src 192.168.1.2
