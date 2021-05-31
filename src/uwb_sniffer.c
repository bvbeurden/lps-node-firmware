/*
 *    ||          ____  _ __
 * +------+      / __ )(_) /_______________ _____  ___
 * | 0xBC |     / __  / / __/ ___/ ___/ __ `/_  / / _ \
 * +------+    / /_/ / / /_/ /__/ /  / /_/ / / /_/  __/
 *  ||  ||    /_____/_/\__/\___/_/   \__,_/ /___/\___/
 *
 * LPS node firmware.
 *
 * Copyright 2016, Bitcraze AB
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Foobar is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Foobar.  If not, see <http://www.gnu.org/licenses/>.
 */
/* uwb_sniffer.c: Uwb sniffer implementation */

#include "uwb.h"

#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <math.h>
#include <unistd.h>

#include "cfg.h"
#include "led.h"

#include "libdw1000.h"

#include "FreeRTOS.h"
#include "task.h"
#include "uwb.h"
#include "dwOps.h"
#include "mac.h"

#define NSLOTS 8
#define NRATIOHIST 5

#define PREAMBLE_LENGTH_S ( 128 * 1017.63e-9 )
#define PREAMBLE_LENGTH (uint64_t)( PREAMBLE_LENGTH_S * 499.2e6 * 128 )

// Guard length to account for clock drift and time of flight
#define TDMA_GUARD_LENGTH_S ( 1e-6 )
#define TDMA_GUARD_LENGTH (uint64_t)( TDMA_GUARD_LENGTH_S * 499.2e6 * 128 )

#define TDMA_EXTRA_LENGTH_S ( 300e-6 )
#define TDMA_EXTRA_LENGTH (uint64_t)( TDMA_EXTRA_LENGTH_S * 499.2e6 * 128 )



static const uint8_t base_address[] = {0,0,0,0,0,0,0xcf,0xbc};

// This context struct contains all the required global values of the algorithm
static struct ctx_s {
  int anchorId;

  // Information about latest transmitted packet
  uint32_t txTime; // In UWB clock ticks
  uint8_t txTime_high8;
  uint32_t nextTxTick;
  uint32_t latestPacket;
  uint32_t latestPacketRx;
  uint8_t latestPacketRx_high8;
  uint32_t pollPacket;
  uint32_t pollPacketRx;
  uint32_t answerPacket;
  uint32_t answerPacketRx;
  double tof;
  uint32_t clockOffset;
  double clockRatio;
  double clockRatioHist[NRATIOHIST];
  int ratioUpdateIndex;
  //uint32_t rxTimestampsInCurrentClock[NSLOTS];
  //uint32_t rxTimestampsInRemoteClock[NSLOTS];
} ctx;

typedef struct {
  uint32_t txTimeStamp;
  uint32_t remoteTx;
  uint32_t remoteRx;
  uint32_t txtimelow32;
  uint8_t txtimehigh8;
  uint32_t latestrxlow32;
  uint8_t latestrxhigh8;
  uint32_t rxEstimation;
} __attribute__((packed)) rangePacketHeader3_t;

typedef struct {
  rangePacketHeader3_t header;
} __attribute__((packed)) rangePacketS_t;


static void adjustTxRxTime(dwTime_t *time)
{
  time->full = (time->full & ~((1 << 9) - 1)) + (1 << 9);
}

static void getClockRatio(uint64_t new_receive_rx, uint32_t new_receive_tx){
  double tx_delay, rx_delay, ratio_tx_rx;


  tx_delay = new_receive_tx - ctx.latestPacket;
  rx_delay = new_receive_rx -  (ctx.latestPacketRx + ((uint64_t) ctx.latestPacketRx_high8 << 32 ));

  ratio_tx_rx = (tx_delay )/ rx_delay;


  if ( fabs(ratio_tx_rx - 1) < 2e-5 ){
    ctx.clockRatioHist[ctx.ratioUpdateIndex] = ratio_tx_rx;
    ctx.ratioUpdateIndex = (ctx.ratioUpdateIndex + 1) % NRATIOHIST;

    for (int i = 0; i < NRATIOHIST; i++){
        int counter = 0;
        for (int j = 0; j < NRATIOHIST; j++){
          if (ctx.clockRatioHist[i] < ctx.clockRatioHist[j] ){
            counter++;
          }else if (ctx.clockRatioHist[i] > ctx.clockRatioHist[j]){
            counter--;
          }
        }

        if (counter == 0){
            ctx.clockRatio = ctx.clockRatioHist[i];
        }
    }

    //ctx.clockRatio = ctx.clockRatioHist[1];
  }

  return;
}

static void wirelessSynch(){
  double tround1, treply1, treply2, tround2, tof, distance;

  tround1 = ctx.answerPacketRx - ctx.pollPacket;
  treply1 = ctx.answerPacket - ctx.pollPacketRx;
  tround2 = ctx.latestPacketRx - ctx.answerPacket;
  treply2 = ctx.latestPacket - ctx.answerPacketRx;
  tof = ((tround1*tround2) - (treply1*treply2)) / (tround1 + tround2 + treply1 + treply2);

  distance = ctx.latestPacketRx - ctx.latestPacket;

  if ( tof > 32500 && tof < 33000 ){
    ctx.tof = tof;
  }
  ctx.clockOffset = distance - ctx.tof;

  return;
}


static uint32_t estimateRemoteRx(){

  double remote_rx = ctx.txTime - ctx.clockOffset;

  double timediff = ctx.txTime - ctx.latestPacketRx;
  double correction = timediff * (ctx.clockRatio - 1) + ctx.tof;

  remote_rx += correction;

  return (unsigned int) remote_rx;
}

static void estimateRxInOtherAnchor(uint32_t rangingPacketRx){

  double remote_rx = rangingPacketRx - ctx.clockOffset;

  double timediff = rangingPacketRx - ctx.latestPacketRx;
  double correction = timediff * (ctx.clockRatio - 1);

  remote_rx += correction;

  printf(" rrx: %08x", (unsigned int) remote_rx);

  //return (unsigned int)remote_rx;
}

static dwTime_t findTransmitTimeAsSoonAsPossible(dwDevice_t *dev)
{
  dwTime_t transmitTime = { .full = 0 };
  dwGetSystemTimestamp(dev, &transmitTime);

  // Add guard and preamble time
  transmitTime.full += TDMA_GUARD_LENGTH;
  transmitTime.full += PREAMBLE_LENGTH;

  // And some extra
  transmitTime.full += TDMA_EXTRA_LENGTH;

  adjustTxRxTime(&transmitTime);
  return transmitTime;
}

static int populateTxData(rangePacketS_t *rangePacket)
{
  rangePacket->header.txTimeStamp = ctx.txTime;
  rangePacket->header.remoteRx =  ctx.latestPacketRx;
  rangePacket->header.remoteTx = ctx.latestPacket;
  rangePacket->header.txtimelow32 = ctx.txTime;
  rangePacket->header.txtimehigh8 = ctx.txTime_high8;
  rangePacket->header.latestrxlow32 = ctx.latestPacketRx;
  rangePacket->header.latestrxhigh8 = ctx.latestPacketRx_high8;
  rangePacket->header.rxEstimation = estimateRemoteRx();
  return sizeof(rangePacket->header);
}

// Set TX data in the radio TX buffer
static void setTxData(dwDevice_t *dev)
{
  static packet_t txPacket;
  static bool firstEntry = true;

  if (firstEntry) {
    MAC80215_PACKET_INIT(txPacket, MAC802154_TYPE_DATA);

    memcpy(txPacket.sourceAddress, base_address, 8);
    txPacket.sourceAddress[0] = ctx.anchorId;
    memcpy(txPacket.destAddress, base_address, 8);
    txPacket.destAddress[0] = 0xff;

    firstEntry = false;
  }
  int rangePacketSize = populateTxData((rangePacketS_t *)txPacket.payload);

  dwSetData(dev, (uint8_t*)&txPacket, MAC802154_HEADER_LENGTH + rangePacketSize );
}

// Setup the radio to send a packet
static void setupTx(dwDevice_t *dev)
{
  dwTime_t txTime = findTransmitTimeAsSoonAsPossible(dev);

  ctx.txTime = txTime.low32;
  ctx.txTime_high8 = txTime.high8;

  setTxData(dev);

  dwNewTransmit(dev);
  dwSetDefaults(dev);
  dwSetTxRxTime(dev, txTime);
  dwStartTransmit(dev);
}


static void setupRx(dwDevice_t *dev)
{
  dwNewReceive(dev);
  dwSetDefaults(dev);
  dwStartReceive(dev);
}

static uint32_t startNextEvent(dwDevice_t *dev)
{
  dwIdle(dev);
  uint32_t now = xTaskGetTickCount();

  if (ctx.nextTxTick < now){

    setupTx(dev);
    //printf("tx %02x%08x \r\n", (unsigned int) ctx.txTime_high8, (unsigned int) ctx.txTime);

    ctx.pollPacket = ctx.latestPacket;
    ctx.pollPacketRx = ctx.latestPacketRx;

    int delay_ms = ctx.anchorId; // having the exact same freq can result in clashes for many packets in a row
    // therefore manually select id 21 and 24 for the two sniffers
    ctx.nextTxTick += M2T(delay_ms);
  } else {
    setupRx(dev);
  }

  return ctx.nextTxTick - now;
}

static void handleRxPacket(dwDevice_t *dev)
{
  static dwTime_t arrival;
  static packet_t rxPacket;

  //if (event == eventPacketReceived) {
  int dataLength = dwGetDataLength(dev);
  dwGetRawReceiveTimestamp(dev, &arrival);
  dwGetData(dev, (uint8_t*)&rxPacket, dataLength);

  dwNewReceive(dev);
  dwSetDefaults(dev);
  dwStartReceive(dev);

  uint32_t latest_timestamp = 0;
  uint32_t answer_tx = 0;
  uint32_t answer_rx = 0;

  int source_address = rxPacket.sourceAddress[0];

  printf("From %02x to %02x @%02x%08x: ", source_address,
                                        rxPacket.destAddress[0],
                                        (unsigned int) arrival.high8,
                                        (unsigned int) arrival.low32);

  for (int i=0; i<(dataLength - MAC802154_HEADER_LENGTH); i++) {
    printf("%02x", rxPacket.payload[i]);
  }

  if (source_address > 20){

    for (int i=0; i<4; i++) {
      latest_timestamp += rxPacket.payload[i] << i*8;
    }

    for (int i=0; i<4; i++) {
      answer_tx += rxPacket.payload[i+4] << i*8;
    }

    for (int i=0; i<4; i++) {
      answer_rx += rxPacket.payload[i+8] << i*8;
    }

    getClockRatio(arrival.full, latest_timestamp);

    ctx.latestPacketRx = arrival.low32;
    ctx.latestPacketRx_high8 = arrival.high8;
    ctx.latestPacket = latest_timestamp;
    ctx.answerPacketRx = answer_rx;
    ctx.answerPacket = answer_tx;

    wirelessSynch();
  }
  else{
    /*printf("From %02x to %02x @%02x%08x: ", source_address,
                                        rxPacket.destAddress[0],
                                        (unsigned int) arrival.high8,
                                        (unsigned int) arrival.low32);

    for (int i=0; i<(dataLength - MAC802154_HEADER_LENGTH); i++) {
      printf("%02x", rxPacket.payload[i]);
    }*/

    //uint32_t rx_in_clock_other_anchor =
    estimateRxInOtherAnchor(arrival.low32);

    //ctx.rxTimestampsInCurrentClock[source_address] = arrival.low32;
    //ctx.rxTimestampsInRemoteClock[source_address] = rx_in_clock_other_anchor;

  }

  printf(" lprx: %08x", (unsigned int) ctx.latestPacketRx);
  printf(" offset: %08x", (unsigned int) ctx.clockOffset);
  printf(" ratio: %0.10f", ctx.clockRatio);
  printf("\r\n");
}

static uint32_t snifferOnEvent(dwDevice_t *dev, uwbEvent_t event)
{
  switch (event) {
    case eventPacketReceived: {
        handleRxPacket(dev);
      }
      break;
    default:
      break;
  }
  uint32_t timeout_ms = startNextEvent(dev);

  return timeout_ms;
}

static void snifferInit(uwbConfig_t * newconfig, dwDevice_t *dev)
{

  ctx.anchorId = newconfig->address[0];
  ctx.txTime = 0;
  ctx.txTime_high8 = 0;
  ctx.nextTxTick = 0;
  ctx.latestPacket = 0;
  ctx.latestPacketRx = 0;
  ctx.latestPacketRx_high8 = 0;
  ctx.pollPacket = 0;
  ctx.pollPacketRx = 0;
  ctx.answerPacket = 0;
  ctx.answerPacketRx = 0;
  ctx.tof = 0;
  ctx.clockOffset = 0;
  ctx.clockRatio = 1.0;
  memset(ctx.clockRatioHist, 1.0, sizeof(ctx.clockRatioHist));
  ctx.ratioUpdateIndex = 0;
  //memset(ctx.rxTimestampsInCurrentClock, 0, sizeof(ctx.rxTimestampsInCurrentClock));
  //memset(ctx.rxTimestampsInRemoteClock, 0, sizeof(ctx.rxTimestampsInRemoteClock));

  // Set the LED for anchor mode
  ledBlink(ledMode, false);
}

uwbAlgorithm_t uwbSnifferAlgorithm = {
  .init = snifferInit,
  .onEvent = snifferOnEvent,
};
