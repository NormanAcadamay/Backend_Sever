const {PrismaClient} =require('@prisma/client')
const prisma = new PrismaClient()

async function run() {
  await prisma.$executeRawUnsafe('DROP Database bekery')
  await prisma.$executeRawUnsafe('CREATE Database bekery')
}
console.log('Reset DB')
run()