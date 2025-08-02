# 🛡️ Namada Privacy Best Practices

> Practical, easy-to-understand advice on how Namada can protect your privacy — and where its protections have limits.

Privacy is a right — and Namada is built to protect it. This page shares best practices for users and developers to maintain strong privacy while using the Namada protocol.

---

## ✅ How Namada Technology Protects Privacy

Namada is a privacy-based blockchain that shields your crypto transactions by **concealing wallet addresses, transaction history, and portfolio information**. It allows you to send assets anonymously across **IBC chains**, with expansion planned for **Ethereum** and **Solana**.

Key privacy features include:

- **Shielded Transactions:** Hides sender, receiver, and amounts using zk-SNARKs.
- **Multi-Asset Shielded Pool (MASP):** Send, receive, and bridge assets privately — like sending money in an envelope rather than a postcard.
- **Cross-Chain Privacy:** Shield assets on IBC, and soon on Ethereum and Solana.
- **Shield for Yield Rewards:** Earn NAM tokens whenever you shield transactions — your privacy strengthens the network.
- **Low Fees & Familiar Assets:** Works with assets you likely already hold.

---

## ⚠️ Where Namada Technology Does *Not* Protect Privacy

Even with strong on-chain privacy, you can still leak information if you are not careful:

- **IP Address Tracking:** Using Namada without Tor or a VPN exposes your network location.
- **Address Reuse:** Using the same shielded address repeatedly can link your transactions.
- **Transparent Transactions:** Any unshielded activity exposes amounts and addresses.
- **Off-Chain Identity Links:** Posting your Namada address publicly or linking it to personal info removes anonymity.
- **Centralized Exchanges:** Exchanges can record and share your deposit/withdrawal history, especially with KYC.

---

## 🛡️ 1. General Privacy Tips

- Prefer using **shielded transactions** over transparent ones.
- Avoid using identifiable addresses or patterns.
- Never reuse addresses — especially transparent ones.

---

## 🔗 2. Bridging

- Use a **separate transparent address** for bridging into Namada.
- After bridging, immediately **shield** your assets.
- Avoid bridging out unless absolutely necessary.
- Use privacy-preserving bridges whenever possible.

---

## 🌀 3. MASP (Multi-Asset Shielded Pool)

- Always store and transact assets **within the MASP**.
- Avoid mixing transparent and shielded actions in the same session.
- Treat MASP as your default wallet.

---

## 🔐 4. View Keys

- Only share your **viewing keys** with trusted parties.
- Never expose your viewing key publicly — it reveals your full transaction history.

---

## ⏳ 5. Transaction Hygiene

- Randomize timing between receiving and sending transactions.
- Consider delaying transactions to reduce linkability.
- Avoid sending exact, unique amounts that could identify you.
- Batch multiple transactions together when possible.

---

## 🌐 6. Social/Off-Chain Behavior

- Use VPNs when accessing wallets or dApps.
- Don’t link shielded addresses to public profiles or social media.
- Avoid sharing screenshots of balances or transactions.
- Keep your device secure with strong passwords and encryption.

---

## 🛡️ 7. Extended Practical Tips for Maximum Privacy

1. **Always choose shielded transactions** over transparent ones.
2. **Enter assets into MASP before sending** — shield first.
3. **Rotate shielded addresses** for different purposes (personal, donations, trading, etc.).
4. **Withdraw directly to shielded addresses** from exchanges.
5. **Separate wallets for different use cases** to prevent activity linking.
6. **Avoid timing patterns** — vary your transaction times.
7. **Be mindful of metadata leaks** in chats, screenshots, or public logs.
8. **Check recipients before sending** — confirm they use shielded addresses.
9. **Stay updated** with the latest Namada software.
10. **Practice good device security** — avoid malware that could expose wallet data.

---

## ✍️ Contribute 
Have improvements or feedback? [Join the discussion →](https://discord.gg/srC76aE6)

