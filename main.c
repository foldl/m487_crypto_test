/**************************************************************************//**
*
* @copyright (C) 2019 Nuvoton Technology Corp. All rights reserved.
*
* SPDX-License-Identifier: Apache-2.0
*
* Change Logs:
* Date            Author       Notes
* 2020-1-16       Wayne        First version
*
******************************************************************************/

#include <rtconfig.h>
#include <rtdevice.h>
#include <drv_gpio.h>
#include <stdio.h>
#include <string.h>

#include "hwcrypto.h"

/* defined the LEDR pin: PH0 */
#define LEDR   NU_GET_PININDEX(NU_PH, 0)
#define LEDY   NU_GET_PININDEX(NU_PH, 1)
#define LEDG   NU_GET_PININDEX(NU_PH, 2)

void blink_it(int led)
{
    int counter = 0;
    while (counter++ < 10)
    {
        rt_pin_write(led, PIN_HIGH);
        rt_thread_mdelay(500);
        rt_pin_write(led, PIN_LOW);
        rt_thread_mdelay(500);
    }
}

#define DELAY  50

void blink_once(int led)
{
    rt_pin_write(led, PIN_LOW);
    rt_thread_mdelay(DELAY);
    rt_pin_write(led, PIN_HIGH);
    rt_thread_mdelay(DELAY);
}

#define print rt_kprintf

void print_hex(const uint8_t *buffer, int len)
{
    int i;
    for (i = 0; i < len; i++)
        print("%02X", buffer[i]);
    print("\n");
}

void test_rng(struct rt_hwcrypto_device *device)
{
    struct rt_hwcrypto_ctx *ctx = rt_hwcrypto_rng_create(device);
    int i;
    static uint32_t counts[256] = {0};

    memset(counts, 0, sizeof(counts));

#define CNT_THRES   700

    print("generating 256 * 1000 random bytes:\n");
    for (i = 0; i < 256 * 1000 / 4; i++)
    {
        uint32_t v = rt_hwcrypto_rng_update_ctx(ctx);
        counts[v & 0xff]++; v >>= 8;
        counts[v & 0xff]++; v >>= 8;
        counts[v & 0xff]++; v >>= 8;
        counts[v & 0xff]++;
    }

    rt_hwcrypto_rng_destroy(ctx);

    print("a simple check: if random bytes follow an uniform distribution...");
    int flag = 0;
    for (i = 0; i < 256; i++)
    {
        //print("%d: %d\n", i, counts[i]);
        if (counts[i] < CNT_THRES)
            flag = 1;
    }
    print("%s\n", flag == 0 ? "PASS" : "FAIL");
}

void test_crc(struct rt_hwcrypto_device *device)
{
    // CRC-32
    // https://www.lddgo.net/encrypt/crc
    const struct hwcrypto_crc_cfg cfg =
    {
        .last_val = 0xffffffff,
        .poly = 0x04C11DB7,
        .width = 32,
        .xorout = 0xffffffff,
        .flags = CRC_FLAG_REFIN | CRC_FLAG_REFOUT,
    };

    struct rt_hwcrypto_ctx *ctx = rt_hwcrypto_crc_create(device, HWCRYPTO_CRC_CRC32);
    if (ctx == 0)
    {
        print("HWCRYPTO_CRC_CRC32 not available!\n");
        return;
    }

    rt_hwcrypto_crc_cfg(ctx, (struct hwcrypto_crc_cfg *)&cfg);

    const static uint8_t value[] = {1,2,3,4};
    uint32_t crc = rt_hwcrypto_crc_update(ctx, value, sizeof(value));

    print("%s\n", crc == 0xB63CFBCD ? "PASS" : "FAIL");

    rt_hwcrypto_crc_destroy(ctx);
}

void test_hash(struct rt_hwcrypto_device *device)
{
    const static uint8_t result[] = {0x9f, 0x64, 0xa7, 0x47, 0xe1, 0xb9, 0x7f, 0x13,
            0x1f, 0xab, 0xb6, 0xb4, 0x47, 0x29, 0x6c, 0x9b, 0x6f, 0x02, 0x01, 0xe7,
            0x9f, 0xb3, 0xc5, 0x35, 0x6e, 0x6c, 0x77, 0xe8, 0x9b, 0x6a, 0x80, 0x6a};
    int i;
    struct rt_hwcrypto_ctx *ctx = rt_hwcrypto_hash_create(device, HWCRYPTO_TYPE_SHA256);
    if (ctx == 0)
    {
        print("HWCRYPTO_TYPE_SHA256 not available!\n");
        return;
    }

    const static uint8_t value[] = {1,2,3,4};
    static uint8_t hash[256 / 8];
    rt_err_t err = rt_hwcrypto_hash_update(ctx, value, sizeof(value));
    if (err)
    {
        print("rt_hwcrypto_hash_update: %d\n", err);
    }

    rt_hwcrypto_hash_finish(ctx, hash, 32);
    rt_hwcrypto_hash_destroy(ctx);

    print("%s\n", memcmp(hash, result, sizeof(hash)) == 0 ? "PASS" : "FAIL");
}

void test_aes_128(struct rt_hwcrypto_device *device)
{
    struct rt_hwcrypto_ctx *ctx = rt_hwcrypto_symmetric_create(device, HWCRYPTO_TYPE_AES_ECB);
    if (ctx == 0)
    {
        print("HWCRYPTO_TYPE_AES_ECB not available!\n");
        return;
    }

    const static uint8_t key[128 / 8] = {1,2,3,4};
    const static uint8_t iv[16] = {4};
    static uint8_t msg[16] = {5,6,7,8};
    static uint8_t enc[16] = {};
    static uint8_t dec[16] = {};

    rt_hwcrypto_symmetric_setkey(ctx, key, sizeof(key) * 8);
    rt_hwcrypto_symmetric_setiv(ctx, key, sizeof(iv));

    rt_err_t err = rt_hwcrypto_symmetric_crypt(ctx, HWCRYPTO_MODE_ENCRYPT, sizeof(msg), msg, enc);
    if (err)
    {
        print("ENCRYPT err: %d\n", err);
    }
    err = rt_hwcrypto_symmetric_crypt(ctx, HWCRYPTO_MODE_DECRYPT, sizeof(msg), enc, dec);
    if (err)
    {
        print("DECRYPT err: %d\n", err);
    }

    rt_hwcrypto_symmetric_destroy(ctx);

    print("%s\n", memcmp(dec, msg, sizeof(msg)) == 0 ? "PASS" : "FAIL");
}

void test_gcm(struct rt_hwcrypto_device *device)
{
    struct rt_hwcrypto_ctx *ctx = rt_hwcrypto_symmetric_create(device, HWCRYPTO_TYPE_GCM);
    if (ctx == 0)
    {
        print("HWCRYPTO_TYPE_GCM not available!\n");
        return;
    }
    rt_hwcrypto_symmetric_destroy(ctx);
}

#define run_test(msg, fun)  do { print("run test: %s\n", msg); fun(dev); } while (0)

void main_test(void *dummy)
{
    int counter = 0;

    /* set LEDR1 pin mode to output */
    rt_pin_mode(LEDR, PIN_MODE_OUTPUT);
    rt_pin_mode(LEDY, PIN_MODE_OUTPUT);
    rt_pin_mode(LEDG, PIN_MODE_OUTPUT);

    for (counter = 0; counter < 3; counter++)
    {
        blink_once(LEDR);
        blink_once(LEDY);
        blink_once(LEDG);
    }

    struct rt_hwcrypto_device * dev = rt_hwcrypto_dev_default();

    run_test("RNG", test_rng);
    run_test("CRC32", test_crc);
    run_test("SHA256", test_hash);
    run_test("AES-128", test_aes_128);

    while (1)
    {
        blink_once(LEDR);
        blink_once(LEDY);
        blink_once(LEDG);
    }
}

int main(int argc, char **argv)
{
    rt_thread_t tid = rt_thread_create("t", main_test, NULL,
               1024,
               5,
               50);
    rt_thread_startup(tid);

    return 0;
}
