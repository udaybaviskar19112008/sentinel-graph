import { Dropzone } from '@/components/Dropzone'
import { LiveTerminal } from '@/components/LiveTerminal'
import { RiskGauge } from '@/components/RiskGauge'
import { TopologyMap } from '@/components/TopologyMap'

/**
 * Upload, live telemetry and the topology map for the current scan.
 *
 * The socket is owned by the App shell, not this page, so leaving for another route
 * mid-scan does not close it; the store keeps the results for when the user returns.
 */
export function LiveDetonation({ onFile }: { onFile: (file: File) => void }) {
  return (
    <div className="grid h-full w-full grid-cols-12 grid-rows-1 gap-4">
      <aside className="col-span-3 flex min-h-0 flex-col gap-4">
        <Dropzone onFile={onFile} />
        <div className="min-h-0 flex-1">
          <LiveTerminal />
        </div>
      </aside>

      <section className="relative col-span-9 min-h-0 overflow-hidden rounded-xl">
        <TopologyMap />
        <RiskGauge className="absolute right-4 top-4" />
      </section>
    </div>
  )
}
