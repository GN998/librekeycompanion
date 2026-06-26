package com.token2.lkcompanion.fidoui

import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.ImageButton
import android.widget.TextView
import androidx.recyclerview.widget.RecyclerView
import com.token2.lkcompanion.R
import com.token2.lkcompanion.fido.ctap.Ctap2Client

class PasskeyAdapter(
    private val onDelete: (Ctap2Client.Passkey) -> Unit,
    private val onInfo: ((Ctap2Client.Passkey) -> Unit)? = null,
) : RecyclerView.Adapter<PasskeyAdapter.VH>() {

    private var items: List<Ctap2Client.Passkey> = emptyList()

    fun submit(list: List<Ctap2Client.Passkey>) { items = list; notifyDataSetChanged() }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): VH {
        val v = LayoutInflater.from(parent.context).inflate(R.layout.item_passkey, parent, false)
        return VH(v)
    }

    override fun getItemCount() = items.size

    override fun onBindViewHolder(holder: VH, position: Int) {
        val p = items[position]
        holder.rp.text = p.rpId
        holder.user.text = p.userDisplayName ?: p.userName ?: "(no user name)"
        holder.delete.setOnClickListener { onDelete(p) }
        holder.itemView.setOnClickListener { onInfo?.invoke(p) }
    }

    class VH(v: View) : RecyclerView.ViewHolder(v) {
        val rp: TextView = v.findViewById(R.id.pkRp)
        val user: TextView = v.findViewById(R.id.pkUser)
        val delete: ImageButton = v.findViewById(R.id.pkDelete)
    }
}
