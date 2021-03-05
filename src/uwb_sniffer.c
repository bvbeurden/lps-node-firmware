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
#include <unistd.h>

#include "cfg.h"
#include "led.h"

#include "libdw1000.h"

#include "FreeRTOS.h"
#include "task.h"
#include "uwb.h"
#include "dwOps.h"
#include "mac.h"

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
  uint32_t nextTxTick;
  uint32_t latestPacket;
  uint32_t latestPacketRx;
  uint32_t pollPacket;
  uint32_t pollPacketRx;
  uint32_t answerPacket;
  uint32_t answerPacketRx;
} ctx;

typedef struct {
  uint32_t txTimeStamp;
  uint32_t remoteTx;
  uint32_t remoteRx;
} __attribute__((packed)) rangePacketHeader3_t;

typedef struct {
  rangePacketHeader3_t header;
} __attribute__((packed)) rangePacketS_t;


static void adjustTxRxTime(dwTime_t *time)
{
  time->full = (time->full & ~((1 << 9) - 1)) + (1 << 9);
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
    printf("tx %08x \r\n", (unsigned int) ctx.txTime);

    ctx.pollPacket = ctx.latestPacket;
    ctx.pollPacketRx = ctx.latestPacketRx;

    int delay_ms = 22 + ctx.anchorId; // having the exact same freq can result in clashes for many packets in a row
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

  if (cfgIsBinaryMode()) {
    write(STDOUT_FILENO, "\xbc", 1);
    write(STDOUT_FILENO, &arrival.full, 5);
    write(STDOUT_FILENO, &rxPacket.sourceAddress[0], 1);
    write(STDOUT_FILENO, &rxPacket.destAddress[0], 1);
    dataLength -= MAC802154_HEADER_LENGTH;
    write(STDOUT_FILENO, &dataLength, 2);
    write(STDOUT_FILENO, rxPacket.payload, dataLength);
    write(STDOUT_FILENO, &dataLength, 2);  // Length repeated for sync detection
  } else {
    printf("From %02x to %02x @%02x%08x: ", rxPacket.sourceAddress[0],
                                          rxPacket.destAddress[0],
                                          (unsigned int) arrival.high8,
                                          (unsigned int) arrival.low32);

    for (int i=0; i<(dataLength - MAC802154_HEADER_LENGTH); i++) {
      printf("%02x", rxPacket.payload[i]);
    }
    for (int i=0; i<4; i++) {
      latest_timestamp += rxPacket.payload[i] << i*8;
    }

    // if necessary use bitwise operators to get the bytes in the correct order (left and right shift and & operator)
    printf("\r\n");
    for (int i=4; i<8; i++) {
      answer_tx += rxPacket.payload[i] << i*8;
    }
    printf("\r\n");
    for (int i=8; i<12; i++) {
      answer_rx += rxPacket.payload[i] << i*8;
    }
  }
  ctx.latestPacketRx = arrival.low32;
  ctx.latestPacket = latest_timestamp;
  ctx.answerPacketRx = answer_rx;
  ctx.answerPacket = answer_tx;
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
  // Set the LED for anchor mode
  printf("initialising \r\n");
  ctx.anchorId = newconfig->address[0];
  ctx.txTime = 0;
  ctx.nextTxTick = 0;
  ctx.latestPacket = 0;
  ctx.latestPacketRx = 0;
  ctx.pollPacket = 0;
  ctx.pollPacketRx = 0;
  ctx.answerPacket = 0;
  ctx.answerPacketRx = 0;
  ledBlink(ledMode, false);
}

uwbAlgorithm_t uwbSnifferAlgorithm = {
  .init = snifferInit,
  .onEvent = snifferOnEvent,
};
