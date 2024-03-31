package ge.ibsu.demo.services;

import ge.ibsu.demo.entities.Film;
import ge.ibsu.demo.repositories.FilmRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;

@Service
public class FilmService {

    @Autowired
    private FilmRepository filmRepository;

    public Page<Film> searchFilms(String title, String description, Integer releaseYear, String language, Pageable pageable) {
        return filmRepository.findByTitleContainingIgnoreCaseAndDescriptionContainingIgnoreCaseAndReleaseYearAndLanguage(
                title, description, releaseYear, language, pageable);
    }
}
