package com.token2.lkcompanion.fidoui

import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.ImageButton
import android.widget.TextView
import androidx.recyclerview.widget.RecyclerView
import com.token2.lkcompanion.R
import com.token2.lkcompanion.fido.ctap.Ctap2Client

/**
 * Renders enrolled fingerprints. Tapping a row offers rename; the trash button
 * removes. Reuses item_passkey.xml's two-line + button shape via item_fingerprint.xml.
 */
class FingerprintAdapter(
    private val onRemove: (Ctap2Client.Fingerprint) -> Unit,
    private val onRename: (Ctap2Client.Fingerprint) -> Unit,
) : RecyclerView.Adapter<FingerprintAdapter.VH>() {

    private var items: List<Ctap2Client.Fingerprint> = emptyList()

    fun submit(list: List<Ctap2Client.Fingerprint>) { items = list; notifyDataSetChanged() }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): VH {
        val v = LayoutInflater.from(parent.context).inflate(R.layout.item_fingerprint, parent, false)
        return VH(v)
    }

    override fun getItemCount() = items.size

    override fun onBindViewHolder(holder: VH, position: Int) {
        val f = items[position]
        holder.name.text = f.name?.ifBlank { null } ?: "(unnamed fingerprint)"
        holder.id.text = "ID ${f.templateIdHex.take(12)}${if (f.templateIdHex.length > 12) "…" else ""}"
        holder.remove.setOnClickListener { onRemove(f) }
        holder.itemView.setOnClickListener { onRename(f) }
    }

    class VH(v: View) : RecyclerView.ViewHolder(v) {
        val name: TextView = v.findViewById(R.id.fpName)
        val id: TextView = v.findViewById(R.id.fpId)
        val remove: ImageButton = v.findViewById(R.id.fpRemove)
    }
}
