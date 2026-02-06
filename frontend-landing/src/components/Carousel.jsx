import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';

// Import ALL images from assets
import img1 from '../assets/Captura de pantalla de 2026-02-03 18-36-24.png';
import img2 from '../assets/Captura de pantalla de 2026-02-03 18-37-17.png';
import img3 from '../assets/Captura de pantalla de 2026-02-03 18-37-47.png';
import img4 from '../assets/Captura de pantalla de 2026-02-03 18-38-31.png';
import img5 from '../assets/Captura de pantalla de 2026-02-03 18-39-11.png';
import img6 from '../assets/screen.png';
import img7 from '../assets/descarga.jpeg';
import img8 from '../assets/images (1).jpeg';
import img9 from '../assets/images (2).jpeg';
import img10 from '../assets/images (22).jpeg';
import img11 from '../assets/images (23).jpeg';
import img12 from '../assets/images (24).jpeg';
import img13 from '../assets/images (25).jpeg';
import img14 from '../assets/images (3).jpeg';
import img15 from '../assets/images (33).jpeg';
import img16 from '../assets/images.jpeg';

const allImages = [img1, img2, img3, img4, img5, img6, img7, img8, img9, img10, img11, img12, img13, img14, img15, img16];

const Carousel = () => {
    const [currentIndex, setCurrentIndex] = useState(0);
    const [shuffledImages, setShuffledImages] = useState([]);

    useEffect(() => {
        // Shuffle images on mount
        const shuffled = [...allImages].sort(() => Math.random() - 0.5);
        setShuffledImages(shuffled);
    }, []);

    useEffect(() => {
        if (shuffledImages.length === 0) return;

        const timer = setInterval(() => {
            setCurrentIndex((prev) => (prev + 1) % shuffledImages.length);
        }, 5000);

        return () => clearInterval(timer);
    }, [shuffledImages]);

    if (shuffledImages.length === 0) return null;

    return (
        <div className="relative w-full h-full overflow-hidden rounded-3xl">
            <AnimatePresence mode="wait">
                <motion.img
                    key={currentIndex}
                    src={shuffledImages[currentIndex]}
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                    exit={{ opacity: 0 }}
                    transition={{ duration: 1.5 }}
                    className="w-full h-full object-cover"
                    style={{ aspectRatio: '1/1' }}
                />
            </AnimatePresence>
            <div className="absolute bottom-4 right-4 flex gap-1 flex-wrap justify-end max-w-[80%]">
                {shuffledImages.map((_, i) => (
                    <div
                        key={i}
                        className={`w-1.5 h-1.5 rounded-full transition-all ${i === currentIndex ? 'bg-primary w-4' : 'bg-white/20'}`}
                    />
                ))}
            </div>
        </div>
    );
};

export default Carousel;
