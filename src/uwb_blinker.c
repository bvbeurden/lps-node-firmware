/*
 *    ||          ____  _ __
 * +------+      / __ )(_) /_______________ _____  ___
 * | 0xBC |     / __  / / __/ ___/ ___/ __ `/_  / / _ \
 * +------+    / /_/ / / /_/ /__/ /  / /_/ / / /_/  __/
 *  ||  ||    /_____/_/\__/\___/_/   \__,_/ /___/\___/
 *
 * LPS node firmware.
 *
 * Copyright 2018, Bitcraze AB
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * uwb_tdoa_anchor3.c is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with uwb_tdoa_anchor3.c. If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "FreeRTOS.h"
#include "task.h"
#include "uwb.h"
#include "mac.h"

#define PREAMBLE_LENGTH_S ( 128 * 1017.63e-9 )
#define PREAMBLE_LENGTH (uint64_t)( PREAMBLE_LENGTH_S * 499.2e6 * 128 )

// Guard length to account for clock drift and time of flight
#define TDMA_GUARD_LENGTH_S ( 1e-6 )
#define TDMA_GUARD_LENGTH (uint64_t)( TDMA_GUARD_LENGTH_S * 499.2e6 * 128 )

#define TDMA_EXTRA_LENGTH_S ( 300e-6 )
#define TDMA_EXTRA_LENGTH (uint64_t)( TDMA_EXTRA_LENGTH_S * 499.2e6 * 128 )



// Useful constants
static const uint8_t base_address[] = {0,0,0,0,0,0,0xcf,0xbc};

// This context struct contains all the required global values of the algorithm
static struct ctx_s {
  int anchorId;

  // Information about latest transmitted packet
  uint32_t txTime; // In UWB clock ticks
  uint32_t nextTxTick;
} ctx;

typedef struct {
  uint32_t txTimeStamp;
} __attribute__((packed)) rangePacketHeader3_t;

typedef struct {
  rangePacketHeader3_t header;
} __attribute__((packed)) rangePacket3_t;

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

static int populateTxData(rangePacket3_t *rangePacket)
{
  rangePacket->header.txTimeStamp = ctx.txTime;

  return sizeof(ctx.txTime);
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
  int rangePacketSize = populateTxData((rangePacket3_t *)txPacket.payload);

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

static uint32_t startNextEvent(dwDevice_t *dev)
{
  dwIdle(dev);
  uint32_t now = xTaskGetTickCount();

  if (ctx.nextTxTick < now){
    ctx.nextTxTick += M2T(21);
    setupTx(dev);
  }

  return ctx.nextTxTick - now;
}

// Initialize/reset the agorithm
static void blinkerInit(uwbConfig_t * config, dwDevice_t *dev)
{
  printf("initialising \n");
  ctx.anchorId = config->address[0];
  ctx.txTime = 0;
  ctx.nextTxTick = 0;
}

// Called for each DW radio event
static uint32_t blinkerUwbEvent(dwDevice_t *dev, uwbEvent_t event)
{
  uint32_t timeout_ms = startNextEvent(dev);
  return timeout_ms; // timeout_ms;
}

uwbAlgorithm_t uwbBlinkerAlgorithm = {
  .init = blinkerInit,
  .onEvent = blinkerUwbEvent,
};

