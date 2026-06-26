package com.token2.lkcompanion.oathui

import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.ImageButton
import android.widget.TextView
import androidx.recyclerview.widget.RecyclerView
import com.token2.lkcompanion.R

/**
 * Renders OATH credentials into the shared OTP row layout (item_otp_entry.xml).
 * TOTP rows show a live code with a per-period countdown; non-TOTP rows show a
 * placeholder. Mirrors Token2EntryAdapter so the OTP tab looks identical whether
 * the key uses the Token2 or OATH applet.
 */
class OathEntryAdapter(
    private val onDelete: (OathRepository.Display) -> Unit,
    private val onCopy: (OathRepository.Display) -> Unit,
) : RecyclerView.Adapter<OathEntryAdapter.VH>() {

    private var entries: List<OathRepository.Display> = emptyList()
    private var secondsLeft: Int = 30

    fun submit(list: List<OathRepository.Display>) {
        entries = list
        notifyDataSetChanged()
    }

    fun tick(secondsRemaining: Int) {
        secondsLeft = secondsRemaining
        notifyDataSetChanged()
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): VH {
        val v = LayoutInflater.from(parent.context)
            .inflate(R.layout.item_otp_entry, parent, false)
        return VH(v)
    }

    override fun getItemCount() = entries.size

    override fun onBindViewHolder(holder: VH, position: Int) {
        val e = entries[position]
        holder.title.text = if (e.issuer.isBlank()) e.account else e.issuer
        holder.subtitle.text = e.account
        when {
            e.code != null -> {
                holder.code.text = spaceCode(e.code)
                holder.meta.text = "TOTP • 30s • ${secondsLeft}s left"
            }
            !e.isTotp -> {
                holder.code.text = "— — — — — —"
                holder.meta.text = "HOTP • not shown"
            }
            else -> {
                holder.code.text = "— — — — — —"
                holder.meta.text = "no code"
            }
        }
        holder.delete.setOnClickListener { onDelete(e) }
        holder.copy.visibility = if (e.code != null) View.VISIBLE else View.GONE
        holder.copy.setOnClickListener { onCopy(e) }
    }

    private fun spaceCode(code: String): String =
        if (code.length == 6) "${code.substring(0, 3)} ${code.substring(3)}"
        else if (code.length == 8) "${code.substring(0, 4)} ${code.substring(4)}"
        else code

    class VH(v: View) : RecyclerView.ViewHolder(v) {
        val title: TextView = v.findViewById(R.id.entryTitle)
        val subtitle: TextView = v.findViewById(R.id.entrySubtitle)
        val code: TextView = v.findViewById(R.id.entryCode)
        val meta: TextView = v.findViewById(R.id.entryMeta)
        val copy: ImageButton = v.findViewById(R.id.entryCopy)
        val delete: ImageButton = v.findViewById(R.id.entryDelete)
    }
}
