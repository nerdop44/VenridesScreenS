// Test script para verificar efectos visuales en la barra lateral
// Ejecutar en la consola del navegador (F12) en http://localhost:8080

console.log("=== TEST DE EFECTOS VISUALES ===");

// 1. Verificar que el elemento sidebar existe
const sidebar = document.getElementById("sidebar");
console.log("1. Sidebar element:", sidebar ? "✅ Found" : "❌ Not found");

if (!sidebar) {
    console.error("ERROR: No se encontró el elemento #sidebar");
} else {
    // 2. Verificar clases actuales
    console.log("2. Current classes:", sidebar.className);

    // 3. Probar agregar cada efecto manualmente
    console.log("\n3. Testing effects manually:");

    // Test Deep Shadow
    sidebar.classList.remove('effect-glass-3d', 'effect-neon-glow', 'effect-deep-shadow');
    sidebar.classList.add('effect-deep-shadow');
    console.log("   - Deep Shadow:", sidebar.classList.contains('effect-deep-shadow') ? "✅" : "❌");

    // Test Neon Glow
    sidebar.classList.remove('effect-glass-3d', 'effect-neon-glow', 'effect-deep-shadow');
    sidebar.classList.add('effect-neon-glow');
    console.log("   - Neon Glow:", sidebar.classList.contains('effect-neon-glow') ? "✅" : "❌");

    // Test Glass 3D
    sidebar.classList.remove('effect-glass-3d', 'effect-neon-glow', 'effect-deep-shadow');
    sidebar.classList.add('effect-glass-3d');
    console.log("   - Glass 3D:", sidebar.classList.contains('effect-glass-3d') ? "✅" : "❌");

    // 4. Verificar estilos computados
    const styles = window.getComputedStyle(sidebar);
    console.log("\n4. Computed styles:");
    console.log("   - box-shadow:", styles.boxShadow);
    console.log("   - border:", styles.border);
    console.log("   - backdrop-filter:", styles.backdropFilter);
}

console.log("\n=== FIN DEL TEST ===");
console.log("Si ves los efectos visuales en la pantalla, funcionan correctamente.");
console.log("Si no los ves, hay un problema con el CSS.");
