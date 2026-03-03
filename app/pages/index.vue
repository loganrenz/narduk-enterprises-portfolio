<script setup lang="ts">
useSeoMeta({
  title: 'Narduk Enterprises Portfolio',
  description: 'Showcasing our flagship Cloudflare Pages, FinTech gamification, and high-performance Web Apps.'
})

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
    url: 'https://neon-sewer-raid.narduk.workers.dev',
    icon: 'i-lucide-swords',
    gradient: 'from-fuchsia-500 to-purple-600',
    iconColor: 'text-fuchsia-400',
    badgeColor: 'error',
    tag: 'Game / Edge'
  },
  {
    name: 'Clawdle',
    description: 'Wordle, but with a Claw twist. Daily word puzzles featuring advanced state management and high-fidelity UI animations.',
    url: 'https://clawdle.narduk.workers.dev',
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
    url: 'https://nagolnagemluapleira.narduk.workers.dev',
    icon: 'i-lucide-planet',
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
  }


]
</script>

<template>
  <div class="min-h-screen bg-default selection:bg-primary/30">
    <!-- Hero Section -->
    <div class="relative overflow-hidden pt-24 pb-16 sm:pt-32 sm:pb-24">
      <div class="absolute inset-0 bg-[url('https://res.cloudinary.com/nuxt/image/upload/v1711964175/nuxt-ui/bg-hero.svg')] bg-cover bg-center opacity-30 mix-blend-color-dodge"></div>
      
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
          class="group relative flex flex-col transition-all duration-300 hover:shadow-2xl hover:shadow-primary/10 hover:-translate-y-1 bg-elevated border-default backdrop-blur-sm overflow-hidden"
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
            
            <h3 class="text-xl font-bold text-default mb-2 group-hover:text-transparent group-hover:bg-clip-text group-hover:bg-linear-to-r group-hover:from-white group-hover:to-muted transition-all">
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
                trailing-icon="i-heroicons-arrow-up-right-20-solid"
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
