<script setup lang="ts">
useSeo({
  title: 'Narduk Enterprises Portfolio',
  description: 'Showcasing our flagship Cloudflare Pages, FinTech gamification, and high-performance Web Apps.',
})
useWebPageSchema({ name: 'Narduk Enterprises Portfolio', description: 'Showcasing our flagship Cloudflare Pages, FinTech gamification, and high-performance Web Apps.', type: 'CollectionPage' })

definePageMeta({
  layout: false // Use raw layout for premium aesthetic matching the dark background
})

const projects = [
  {
    name: 'Stonx',
    description: 'Our flagship FinTech gamification hub. Features a real-time Trading Canvas, high-fidelity participant simulation, and Redis-backed market execution.',
    url: 'https://stonx.app',
    icon: 'i-lucide-activity',
    gradient: 'from-emerald-400 to-teal-500',
    iconColor: 'text-emerald-400',
    badgeColor: 'success',
    tag: 'FinTech / Real-time'
  },
  {
    name: 'loadtest.dev',
    description: 'A k6-based distributed load testing SaaS platform. Features dynamic Origin Derivation, Apple SSO integration, and visually impactful telemetry grids.',
    url: 'https://loadtest.dev',
    icon: 'i-lucide-globe',
    gradient: 'from-blue-400 to-indigo-500',
    iconColor: 'text-blue-400',
    badgeColor: 'info',
    tag: 'SaaS / Testing'
  },
  {
    name: 'Nuxt 4 Edge Template',
    description: 'A minimal, production-ready starter template designed for maximum performance on Cloudflare Workers and D1 SQLite.',
    url: 'https://github.com/narduk-enterprises/nuxt-v4-template',
    icon: 'i-lucide-rocket',
    gradient: 'from-emerald-400 to-cyan-500',
    iconColor: 'text-emerald-400',
    badgeColor: 'success',
    tag: 'Framework / Edge'
  },
  {
    name: 'Nuxt 4 Template Examples',
    description: 'Full-featured reference implementations for the Nuxt 4 Edge Template, including Auth, Analytics, and Dashboard patterns.',
    url: 'https://github.com/narduk-enterprises/nuxt-v4-template-examples',
    icon: 'i-lucide-library',
    gradient: 'from-indigo-400 to-blue-500',
    iconColor: 'text-indigo-400',
    badgeColor: 'info',
    tag: 'Examples / Boilerplate'
  },
  {
    name: 'iMessage Dictionary',
    description: 'A specialized dictionary for decoding iMessage slang and abbreviations. Built with Nuxt 4 and high-performance WASM processing.',
    url: 'https://dictionary.nard.uk',
    icon: 'i-lucide-book-open',
    gradient: 'from-blue-400 to-indigo-500',
    iconColor: 'text-blue-400',
    badgeColor: 'info',
    tag: 'Utility / WASM'
  },
  {
    name: 'Neon Sewer Raid',
    description: 'A fast-paced, neon-drenched roguelike survival game. High-octane action rendered entirely on the Edge with Nuxt 4.',
    url: 'https://neon-sewer-raid.nard.uk',
    icon: 'i-lucide-swords',
    gradient: 'from-fuchsia-500 to-purple-600',
    iconColor: 'text-fuchsia-400',
    badgeColor: 'error',
    tag: 'Game / Edge'
  },
  {
    name: 'Clawdle',
    description: 'Wordle, but with a Claw twist. Daily word puzzles featuring advanced state management and high-fidelity UI animations.',
    url: 'https://clawdle.nard.uk',
    icon: 'i-lucide-fingerprint',
    gradient: 'from-orange-400 to-red-500',
    iconColor: 'text-orange-400',
    badgeColor: 'warning',
    tag: 'Game / Social'
  },
  {
    name: 'Old Austin Grouch',
    description: 'Comedic Austin nostalgia satire blog. Features curated essays, generative hero imagery, and a highly optimized Edge SSR rendering pipeline.',
    url: 'https://grouch.austin-texas.net',
    icon: 'i-lucide-newspaper',
    gradient: 'from-amber-400 to-orange-500',
    iconColor: 'text-amber-400',
    badgeColor: 'warning',
    tag: 'Media / Content'
  },
  {
    name: 'Circuit Breaker Sales',
    description: 'Massive B2B search catalog migration converting an outdated WooCommerce monolith into a blazing fast SQLite-backed Nuxt 4 application.',
    url: 'https://circuitbreaker.online',
    icon: 'i-lucide-battery-charging',
    gradient: 'from-yellow-400 to-amber-500',
    iconColor: 'text-yellow-400',
    badgeColor: 'warning',
    tag: 'E-commerce'
  },
  {
    name: 'Papa Everett\'s Pizza',
    description: 'A modern, high-performance web experience for ordering pizza. Built on the Nuxt 4 template with Edge-side rendering.',
    url: 'https://papaeverettspizza.com',
    icon: 'i-lucide-pizza',
    gradient: 'from-red-400 to-rose-500',
    iconColor: 'text-red-400',
    badgeColor: 'error',
    tag: 'Food / E-commerce'
  },
  {
    name: 'Austin-Texas.net',
    description: 'Automated scraping engine and event aggregator showcasing live music venues around Austin, Texas. Synchronizes with D1 daily.',
    url: 'https://austin-texas.net',
    icon: 'i-lucide-music',
    gradient: 'from-purple-400 to-fuchsia-500',
    iconColor: 'text-purple-400',
    badgeColor: 'primary',
    tag: 'Aggregator'
  },
  {
    name: 'Nagolnagemluapleira',
    description: 'An interactive, fully narrated planetary report exposing the dual realities of a retro-futuristic society. Complete Nuxt 4 migration.',
    url: 'https://nagolnagemluapleira.nard.uk',
    icon: 'i-lucide-moon',
    gradient: 'from-orange-400 to-red-500',
    iconColor: 'text-orange-400',
    badgeColor: 'warning',
    tag: 'Interactive / SPA'
  },
  {
    name: 'OG Preview',
    description: 'Free tool showing how links appear across social media platforms. Built with Nuxt 4, H3 and automated Open Graph tag validation.',
    url: 'https://ogpreview.app',
    icon: 'i-lucide-share-2',
    gradient: 'from-blue-400 to-cyan-500',
    iconColor: 'text-blue-400',
    badgeColor: 'primary',
    tag: 'Web Tool'
  },
  {
    name: 'Portfolio',
    description: 'The meta-shell for Narduk Enterprises projects. Features refined glassmorphism, dynamic gradients, and a highly optimized portfolio grid.',
    url: 'https://portfolio.nard.uk',
    icon: 'i-lucide-layout',
    gradient: 'from-slate-400 to-gray-500',
    iconColor: 'text-slate-400',
    badgeColor: 'secondary',
    tag: 'Meta / Showcase'
  },
  {
    name: 'AI Media Gen',
    description: 'A powerful edge-optimized generation platform for automated media creation.',
    url: 'https://ai-media-gen.nard.uk',
    icon: 'i-lucide-image',
    gradient: 'from-pink-400 to-rose-500',
    iconColor: 'text-pink-400',
    badgeColor: 'primary',
    tag: 'AI / Generation'
  },
  {
    name: 'Drift Map',
    description: 'Visual map interface for exploring global conceptual drift models connected directly with D1 edge caching.',
    url: 'https://drift-map.nard.uk',
    icon: 'i-lucide-map',
    gradient: 'from-emerald-400 to-green-500',
    iconColor: 'text-emerald-400',
    badgeColor: 'success',
    tag: 'Utility / Geo'
  },
  {
    name: 'Enigma Box',
    description: 'A mysterious cryptographic puzzle adventure built seamlessly over Cloudflare Workers.',
    url: 'https://enigma-box.nard.uk',
    icon: 'i-lucide-box',
    gradient: 'from-violet-400 to-fuchsia-500',
    iconColor: 'text-violet-400',
    badgeColor: 'error',
    tag: 'Game / Puzzle'
  },
  {
    name: 'Flashcard Pro',
    description: 'An advanced spaced-repetition flashcard application tuned for rapid cognitive skill acquisition.',
    url: 'https://flashcard-pro.nard.uk',
    icon: 'i-lucide-layers',
    gradient: 'from-cyan-400 to-blue-500',
    iconColor: 'text-cyan-400',
    badgeColor: 'info',
    tag: 'Education / App'
  },
  {
    name: 'Sailing Passage Map',
    description: 'Highly detailed geographic tracking tool enabling maritime insights and historical passage reconstruction.',
    url: 'https://passages.nard.uk',
    icon: 'i-lucide-anchor',
    gradient: 'from-sky-400 to-indigo-500',
    iconColor: 'text-sky-400',
    badgeColor: 'info',
    tag: 'Maps / Geo'
  },
  {
    name: 'Tiny Invoice',
    description: 'A hyper-minimalist invoicing platform focusing purely on speed, rendering reliability, and absolute simplicity.',
    url: 'https://tiny-invoice.nard.uk',
    icon: 'i-lucide-file-text',
    gradient: 'from-lime-400 to-emerald-500',
    iconColor: 'text-lime-400',
    badgeColor: 'success',
    tag: 'Business / Utility'
  },
  {
    name: 'Video Grab',
    description: 'A streamlined edge utility for scraping, processing, and aggregating highly compressed video clips.',
    url: 'https://video-grab.nard.uk',
    icon: 'i-lucide-video',
    gradient: 'from-fuchsia-400 to-purple-500',
    iconColor: 'text-fuchsia-400',
    badgeColor: 'error',
    tag: 'Media / Extraction'
  }
]
</script>

<template>
  <div class="min-h-screen bg-default selection:bg-primary/30">
    <!-- Hero Section -->
    <div class="relative overflow-hidden pt-24 pb-16 sm:pt-32 sm:pb-24">
      <div class="absolute inset-0 z-[-1] bg-[url('/hero-bg.png')] bg-cover bg-center bg-no-repeat opacity-60 dark:opacity-40 pointer-events-none [mask-image:linear-gradient(to_bottom,black_20%,transparent_100%)] mix-blend-plus-lighter dark:mix-blend-color-dodge"></div>
      <div class="absolute inset-0 z-[-2] bg-[radial-gradient(ellipse_at_top,_var(--tw-gradient-stops))] from-primary-900/20 via-background to-background"></div>
      
      <UContainer class="relative">
        <div class="text-center max-w-2xl mx-auto">
          <UBadge variant="subtle" color="primary" class="mb-6 rounded-full px-4 font-mono text-xs">
            PORTFOLIO.NARD.UK
          </UBadge>
          <h1 class="text-4xl font-display font-extrabold tracking-tight text-default sm:text-6xl mb-6">
            Narduk <span class="text-transparent bg-clip-text bg-linear-to-r from-primary to-info">Enterprises</span>
          </h1>
          <p class="mt-4 text-lg leading-8 text-muted">
            A curated showcase of our flagship cloud applications, high-performance distributed systems, and experimental UI/UX lab products.
          </p>
        </div>
      </UContainer>
    </div>

    <!-- Projects Grid -->
    <UContainer class="pb-24">
      <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">
        <UCard
          v-for="project in projects"
          :key="project.name"
          class="group relative flex flex-col transition-all duration-300 hover:shadow-2xl hover:shadow-primary/20 hover:-translate-y-1 glass-card overflow-hidden"
          :ui="{ body: 'p-0' }"
        >
          <!-- Gradient Hover Effect -->
          <div class="absolute inset-x-0 top-0 h-1 bg-linear-to-r opacity-0 group-hover:opacity-100 transition-opacity duration-300" :class="project.gradient"></div>

          <div class="p-6 flex-1 flex flex-col">
            <div class="flex items-center justify-between mb-4">
              <div class="p-3 rounded-xl bg-muted/80 ring-1 ring-white/5 shadow-inner">
                <UIcon :name="project.icon" class="w-6 h-6" :class="project.iconColor" />
              </div>
              <UBadge variant="soft" :color="project.badgeColor as any" size="sm" class="rounded-lg shadow-sm font-medium">
                {{ project.tag }}
              </UBadge>
            </div>
            
            <h3 class="text-xl font-display font-bold text-default mb-2 group-hover:text-primary transition-colors">
              {{ project.name }}
            </h3>
            
            <p class="text-dimmed text-sm leading-relaxed flex-1 mb-6">
              {{ project.description }}
            </p>
            
            <div class="mt-auto">
              <UButton
                :to="project.url"
                target="_blank"
                variant="ghost"
                color="neutral"
                trailing-icon="i-lucide-arrow-up-right"
                class="hover:bg-muted -ml-2 transition-colors font-medium text-muted hover:text-default"
              >
                Launch Project
              </UButton>
            </div>
          </div>
        </UCard>
      </div>
    </UContainer>
  </div>
</template>
