import test from 'node:test'
import assert from 'node:assert/strict'
import { encodeFunctionData, maxUint256, parseUnits } from 'viem'
import { A, YEAR, createHarness, deadline, deployBase, launchParams, scheduleActions, ticker } from './harness.mjs'

test('timelocked stock delisting preserves self-directed LP exit', async () => {
  const h = createHarness()
  try {
    const { alice } = h.accounts
    const { stock, feed, launchpad } = await deployBase(h)
    await h.write(alice, stock, A.Stock, 'approve', [launchpad, maxUint256])
    await h.write(alice, launchpad, A.Launchpad, 'launch', [await launchParams(h, stock)])
    const record = await h.publicClient.readContract({ address: launchpad, abi: A.Launchpad.abi, functionName: 'launchAt', args: [0n] })
    const locker = await h.publicClient.readContract({ address: launchpad, abi: A.Launchpad.abi, functionName: 'liquidityLocker' })
    await h.increaseTime(YEAR + 1)
    await h.write(alice, locker, A.Locker, 'claim', [record.liquidityLockId])
    const lp = await h.publicClient.readContract({ address: record.pool, abi: A.Pool.abi, functionName: 'balanceOf', args: [alice.address] })

    await scheduleActions(h, launchpad, [{
      functionName: 'configureStock',
      args: [stock, feed, ticker('RHM'), 4 * 24 * 60 * 60, parseUnits('1000', 18), false, false]
    }])

    const preview = await h.publicClient.readContract({ address: record.pool, abi: A.Pool.abi, functionName: 'previewRemoveLiquidity', args: [lp / 2n] })
    const data = encodeFunctionData({
      abi: A.Pool.abi,
      functionName: 'removeLiquidity',
      args: [lp / 2n, preview[0] * 99n / 100n, preview[1] * 99n / 100n, alice.address, await deadline(h)]
    })
    const hash = await h.provider.request({ method: 'eth_sendTransaction', params: [{ from: alice.address, to: record.pool, data, gas: '0x1c9c380' }] })
    const receipt = await h.publicClient.waitForTransactionReceipt({ hash, pollingInterval: 10, timeout: 30_000 })
    assert.equal(receipt.status, 'success')
    assert((await h.publicClient.readContract({ address: record.pool, abi: A.Pool.abi, functionName: 'balanceOf', args: [alice.address] })) > 0n)
  } finally { await h.close() }
})
