#!/bin/bash


function show_usage() {
    echo "Basic usage: $0 [-i <iface>] [-d <seconds>]"
    echo "Example: $0 -i wlan0 -d 5"
    echo "default interface: eth0"
    echo "-d: set a refresh time in seconds"
    exit 0
}

iface=eth0
delay=1

# argument parsing
# see: https://stackoverflow.com/questions/192249/how-do-i-parse-command-line-arguments-in-bash
while [[ $# -gt 0 ]] ; do
    key="$1"
    case $key in
        -h)
        show_usage
        ;;
        -i)
        iface="$2"
        shift # past argument
        shift # past value
        ;;
        -d)
        delay=$2
        shift # past argument
        shift # past value
        ;;
        *)    # unknown option
        shift # past argument
        ;;
    esac
done

txpkts_old="$(cat /sys/class/net/$iface/statistics/tx_packets)"
rxpkts_old="$(cat /sys/class/net/$iface/statistics/rx_packets)"
while true ; do
  sleep "$delay"
  txpkts_new="$(cat /sys/class/net/$iface/statistics/tx_packets)"
  rxpkts_new="$(cat /sys/class/net/$iface/statistics/rx_packets)"
  txpkts="$(($txpkts_new - $txpkts_old))"
  rxpkts="$(($rxpkts_new - $rxpkts_old))"
  echo "tx $txpkts pkts/s - rx $rxpkts pkts/ on interface $iface"
  txpkts_old="$txpkts_new"
  rxpkts_old="$rxpkts_new"
done
