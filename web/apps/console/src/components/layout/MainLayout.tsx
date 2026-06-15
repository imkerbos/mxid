import { AnimatePresence, motion } from 'framer-motion'
import { useLocation } from 'react-router-dom'
import Sidebar from './Sidebar'
import { Toaster } from '../ui/toast'

const pageVariants = {
  initial: { opacity: 0, y: 12 },
  in: { opacity: 1, y: 0 },
  out: { opacity: 0, y: -12 },
}

const pageTransition = {
  type: 'tween' as const,
  ease: 'easeInOut' as const,
  duration: 0.2,
}

export default function MainLayout({ children }: { children: React.ReactNode }) {
  const location = useLocation()

  return (
    <div className="min-h-screen">
      <Toaster />
      <Sidebar />
      <main className="ml-64 min-h-screen">
        <AnimatePresence mode="wait">
          <motion.div
            key={location.pathname}
            initial="initial"
            animate="in"
            exit="out"
            variants={pageVariants}
            transition={pageTransition}
            className="p-6"
          >
            {children}
          </motion.div>
        </AnimatePresence>
      </main>
    </div>
  )
}
